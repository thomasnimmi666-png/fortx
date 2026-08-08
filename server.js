const http = require("http");
const WebSocket = require("ws");
const crypto = require("crypto");
const { Pool } = require("pg");

const PORT = process.env.PORT || 3000;
const ACCESS_CODE = process.env.ACCESS_CODE;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

const GROUP_ADMINS = [
  "saftpresse040",
  "thcliquide"
];

const RESET_LIFETIME = 15 * 60 * 1000;

function send(socket, data) {
  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(data));
  }
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const parts = stored.split(":");

    if (parts.length !== 2) {
      return false;
    }

    const salt = parts[0];
    const originalHash = parts[1];

    const hash = crypto.scryptSync(
      password,
      salt,
      64
    );

    const originalBuffer =
      Buffer.from(originalHash, "hex");

    if (hash.length !== originalBuffer.length) {
      return false;
    }

    return crypto.timingSafeEqual(
      hash,
      originalBuffer
    );
  } catch {
    return false;
  }
}

function createResetToken() {
  return crypto.randomBytes(32).toString("hex");
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender TEXT NOT NULL,
      receiver TEXT,
      text TEXT NOT NULL,
      is_group BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS friends (
      username TEXT NOT NULL,
      friend_username TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (username, friend_username)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_resets (
      token_hash TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      used BOOLEAN DEFAULT FALSE
    )
  `);

  console.log("🗄️ Datenbank bereit");
}

async function cleanOldGroupMessages() {
  await pool.query(`
    DELETE FROM messages
    WHERE is_group = TRUE
    AND created_at < NOW() - INTERVAL '24 hours'
  `);
}

async function cleanExpiredResetTokens() {
  await pool.query(`
    DELETE FROM password_resets
    WHERE expires_at < NOW()
       OR used = TRUE
  `);
}

async function broadcastGroup(data) {
  for (const client of wss.clients) {
    if (
      client.readyState === WebSocket.OPEN &&
      client.username
    ) {
      send(client, data);
    }
  }
}

function isAdmin(username) {
  return GROUP_ADMINS.includes(
    String(username || "").toLowerCase()
  );
}

const server = http.createServer((req, res) => {
  res.setHeader(
    "Access-Control-Allow-Origin",
    "*"
  );

  if (req.url === "/health") {
    res.writeHead(200, {
      "Content-Type": "application/json"
    });

    res.end(
      JSON.stringify({
        status: "ok"
      })
    );

    return;
  }

  res.writeHead(200, {
    "Content-Type":
      "text/plain; charset=utf-8"
  });

  res.end(
    "Privater Messenger Server läuft! 🔐"
  );
});

const wss = new WebSocket.Server({
  server
});

wss.on("connection", (socket) => {
  console.log("📱 Gerät verbunden");

  socket.on("message", async (raw) => {
    try {
      const data =
        JSON.parse(raw.toString());

      /*
       * REGISTRIERUNG
       */

      if (data.type === "register") {
        const username =
          String(data.username || "")
            .trim()
            .toLowerCase();

        const password =
          String(data.password || "");

        const accessCode =
          String(data.accessCode || "");

        if (!ACCESS_CODE) {
          send(socket, {
            type: "error",
            text:
              "Server-Zugangscode fehlt."
          });

          return;
        }

        if (accessCode !== ACCESS_CODE) {
          send(socket, {
            type: "error",
            text:
              "Falscher Zugangscode."
          });

          return;
        }

        if (
          username.length < 3 ||
          username.length > 30 ||
          password.length < 8
        ) {
          send(socket, {
            type: "error",
            text:
              "Benutzername mindestens 3 Zeichen und Passwort mindestens 8 Zeichen."
          });

          return;
        }

        const existing =
          await pool.query(
            `
            SELECT username
            FROM users
            WHERE username = $1
            `,
            [username]
          );

        if (existing.rows.length > 0) {
          send(socket, {
            type: "error",
            text:
              "Benutzername ist bereits vergeben."
          });

          return;
        }

        await pool.query(
          `
          INSERT INTO users
          (username, password_hash)
          VALUES ($1, $2)
          `,
          [
            username,
            hashPassword(password)
          ]
        );

        socket.username = username;

        send(socket, {
          type: "registered",
          username
        });

        console.log(
          `👤 Registriert: ${username}`
        );

        return;
      }

      /*
       * LOGIN
       */

      if (data.type === "login") {
        const username =
          String(data.username || "")
            .trim()
            .toLowerCase();

        const password =
          String(data.password || "");

        const result =
          await pool.query(
            `
            SELECT username, password_hash
            FROM users
            WHERE username = $1
            `,
            [username]
          );

        if (
          result.rows.length === 0 ||
          !verifyPassword(
            password,
            result.rows[0].password_hash
          )
        ) {
          send(socket, {
            type: "error",
            text:
              "Benutzername oder Passwort falsch."
          });

          return;
        }

        socket.username = username;

        send(socket, {
          type: "loggedIn",
          username
        });

        console.log(
          `🔓 Login: ${username}`
        );

        return;
      }

      /*
       * FREUNDE LADEN
       */

      if (data.type === "getFriends") {
        const username =
          socket.username;

        if (!username) {
          send(socket, {
            type: "error",
            text:
              "Nicht angemeldet."
          });

          return;
        }

        const result =
          await pool.query(
            `
            SELECT friend_username
            FROM friends
            WHERE username = $1
            ORDER BY friend_username ASC
            `,
            [username]
          );

        send(socket, {
          type: "friends",
          friends:
            result.rows.map(
              row =>
                row.friend_username
            )
        });

        return;
      }

      /*
       * FREUND HINZUFÜGEN
       */

      if (data.type === "addFriend") {
        const username =
          socket.username;

        const friendUsername =
          String(
            data.username || ""
          )
            .trim()
            .toLowerCase();

        if (!username) {
          send(socket, {
            type: "error",
            text:
              "Nicht angemeldet."
          });

          return;
        }

        if (!friendUsername) {
          send(socket, {
            type: "error",
            text:
              "Bitte einen Benutzernamen eingeben."
          });

          return;
        }

        if (
          username ===
          friendUsername
        ) {
          send(socket, {
            type: "error",
            text:
              "Du kannst dich nicht selbst hinzufügen."
          });

          return;
        }

        const user =
          await pool.query(
            `
            SELECT username
            FROM users
            WHERE username = $1
            `,
            [friendUsername]
          );

        if (user.rows.length === 0) {
          send(socket, {
            type: "error",
            text:
              "Benutzer nicht gefunden."
          });

          return;
        }

        await pool.query(
          `
          INSERT INTO friends
          (username, friend_username)
          VALUES ($1, $2)
          ON CONFLICT DO NOTHING
          `,
          [
            username,
            friendUsername
          ]
        );

        send(socket, {
          type: "friendAdded",
          username:
            friendUsername
        });

        console.log(
          `👥 ${username} hat ${friendUsername} hinzugefügt`
        );

        return;
      }

      /*
       * PRIVATE NACHRICHTEN LADEN
       */

      if (
        data.type ===
        "getPrivateMessages"
      ) {
        const username =
          socket.username;

        const other =
          String(
            data.username || ""
          )
            .trim()
            .toLowerCase();

        if (!username || !other) {
          return;
        }

        const result =
          await pool.query(
            `
            SELECT
              sender,
              receiver,
              text,
              EXTRACT(
                EPOCH FROM created_at
              ) * 1000 AS time
            FROM messages
            WHERE is_group = FALSE
              AND (
                (sender = $1 AND receiver = $2)
                OR
                (sender = $2 AND receiver = $1)
              )
            ORDER BY created_at ASC
            `,
            [
              username,
              other
            ]
          );

        send(socket, {
          type:
            "privateMessages",
          username: other,
          messages:
            result.rows.map(
              row => ({
                from:
                  row.sender,
                to:
                  row.receiver,
                text:
                  row.text,
                time:
                  Number(row.time)
              })
            )
        });

        return;
      }

      /*
       * PASSWORT VERGESSEN
       */

      if (
        data.type ===
        "forgotPassword"
      ) {
        const username =
          String(
            data.username || ""
          )
            .trim()
            .toLowerCase();

        if (!username) {
          send(socket, {
            type: "error",
            text:
              "Bitte Benutzernamen eingeben."
          });

          return;
        }

        const user =
          await pool.query(
            `
            SELECT username
            FROM users
            WHERE username = $1
            `,
            [username]
          );

        if (user.rows.length === 0) {
          send(socket, {
            type:
              "forgotPasswordSent",
            text:
              "Wenn das Konto existiert, wurde eine Anfrage an die Admins gesendet."
          });

          return;
        }

        const requestId =
          crypto
            .randomBytes(16)
            .toString("hex");

        const requestMessage = {
          type:
            "passwordResetRequest",
          requestId,
          username,
          time:
            Date.now()
        };

        for (
          const client
          of wss.clients
        ) {
          if (
            client.readyState ===
              WebSocket.OPEN &&
            client.username &&
            isAdmin(
              client.username
            )
          ) {
            send(
              client,
              requestMessage
            );
          }
        }

        send(socket, {
          type:
            "forgotPasswordSent",
          text:
            "Die Anfrage wurde an die Admins gesendet."
        });

        console.log(
          `🔑 Passwort-Reset angefragt: ${username}`
        );

        return;
      }

      /*
       * RESET-LINK ERSTELLEN
       */

      if (
        data.type ===
        "createPasswordReset"
      ) {
        const admin =
          socket.username;

        if (!isAdmin(admin)) {
          send(socket, {
            type: "error",
            text:
              "Nur Admins dürfen Reset-Links erstellen."
          });

          return;
        }

        const username =
          String(
            data.username || ""
          )
            .trim()
            .toLowerCase();

        const user =
          await pool.query(
            `
            SELECT username
            FROM users
            WHERE username = $1
            `,
            [username]
          );

        if (user.rows.length === 0) {
          send(socket, {
            type: "error",
            text:
              "Benutzer nicht gefunden."
          });

          return;
        }

        await pool.query(
          `
          DELETE FROM password_resets
          WHERE username = $1
          `,
          [username]
        );

        const token =
          createResetToken();

        const tokenHash =
          crypto
            .createHash("sha256")
            .update(token)
            .digest("hex");

        await pool.query(
          `
          INSERT INTO password_resets
          (
            token_hash,
            username,
            expires_at
          )
          VALUES (
            $1,
            $2,
            NOW() + INTERVAL '15 minutes'
          )
          `,
          [
            tokenHash,
            username
          ]
        );

        const baseUrl =
          process.env.APP_URL ||
          "https://fortx.onrender.com";

        const resetUrl =
          `${baseUrl}/?reset=${token}`;

        send(socket, {
          type:
            "passwordResetLink",
          username,
          resetUrl,
          expiresIn:
            RESET_LIFETIME
        });

        console.log(
          `🔗 Reset-Link erstellt für ${username}`
        );

        return;
      }

      /*
       * PASSWORT ZURÜCKSETZEN
       */

      if (
        data.type ===
        "resetPassword"
      ) {
        const token =
          String(data.token || "");

        const newPassword =
          String(
            data.password || ""
          );

        if (
          !token ||
          newPassword.length < 8
        ) {
          send(socket, {
            type: "error",
            text:
              "Das neue Passwort muss mindestens 8 Zeichen haben."
          });

          return;
        }

        const tokenHash =
          crypto
            .createHash("sha256")
            .update(token)
            .digest("hex");

        const result =
          await pool.query(
            `
            SELECT username
            FROM password_resets
            WHERE token_hash = $1
              AND used = FALSE
              AND expires_at > NOW()
            `,
            [tokenHash]
          );

        if (result.rows.length === 0) {
          send(socket, {
            type: "error",
            text:
              "Der Reset-Link ist ungültig oder abgelaufen."
          });

          return;
        }

        const username =
          result.rows[0].username;

        await pool.query(
          `
          UPDATE users
          SET password_hash = $1
          WHERE username = $2
          `,
          [
            hashPassword(
              newPassword
            ),
            username
          ]
        );

        await pool.query(
          `
          UPDATE password_resets
          SET used = TRUE
          WHERE token_hash = $1
          `,
          [tokenHash]
        );

        send(socket, {
          type:
            "passwordResetSuccess",
          username
        });

        console.log(
          `🔐 Passwort geändert: ${username}`
        );

        return;
      }

      /*
       * GRUPPENCHAT LADEN
       */

      if (
        data.type ===
        "getGroupMessages"
      ) {
        if (!socket.username) {
          return;
        }

        await cleanOldGroupMessages();

        const result =
          await pool.query(
            `
            SELECT
              sender AS username,
              text,
              EXTRACT(
                EPOCH FROM created_at
              ) * 1000 AS time
            FROM messages
            WHERE is_group = TRUE
            ORDER BY created_at ASC
            `
          );

        send(socket, {
          type:
            "groupMessages",
          messages:
            result.rows.map(
              row => ({
                username:
                  row.username,
                text:
                  row.text,
                time:
                  Number(row.time)
              })
            )
        });

        return;
      }

      /*
       * GRUPPENCHAT NACHRICHT
       */

      if (
        data.type ===
        "groupMessage"
      ) {
        const username =
          socket.username;

        if (!username) {
          return;
        }

        if (!isAdmin(username)) {
          send(socket, {
            type: "error",
            text:
              "Du darfst im Gruppenchat nur lesen."
          });

          return;
        }

        const text =
          String(
            data.text || ""
          ).trim();

        if (!text) {
          return;
        }

        const result =
          await pool.query(
            `
            INSERT INTO messages
            (
              sender,
              text,
              is_group
            )
            VALUES ($1, $2, TRUE)
            RETURNING
              sender,
              text,
              EXTRACT(
                EPOCH FROM created_at
              ) * 1000 AS time
            `,
            [
              username,
              text
            ]
          );

        const message = {
          username:
            result.rows[0].sender,
          text:
            result.rows[0].text,
          time:
            Number(
              result.rows[0].time
            )
        };

        await broadcastGroup({
          type:
            "groupMessage",
          message
        });

        return;
      }

      /*
       * PRIVATE NACHRICHT
       */

      if (
        data.type ===
        "message"
      ) {
        const from =
          socket.username;

        const to =
          String(
            data.to || ""
          )
            .trim()
            .toLowerCase();

        const text =
          String(
            data.text || ""
          ).trim();

        if (
          !from ||
          !to ||
          !text
        ) {
          return;
        }

        if (text.length > 5000) {
          send(socket, {
            type: "error",
            text:
              "Nachricht ist zu lang."
          });

          return;
        }

        const target =
          await pool.query(
            `
            SELECT username
            FROM users
            WHERE username = $1
            `,
            [to]
          );

        if (
          target.rows.length ===
          0
        ) {
          send(socket, {
            type: "error",
            text:
              "Benutzer nicht gefunden."
          });

          return;
        }

        const result =
          await pool.query(
            `
            INSERT INTO messages
            (
              sender,
              receiver,
              text,
              is_group
            )
            VALUES (
              $1,
              $2,
              $3,
              FALSE
            )
            RETURNING
              EXTRACT(
                EPOCH FROM created_at
              ) * 1000 AS time
            `,
            [
              from,
              to,
              text
            ]
          );

        const message = {
          type:
            "message",
          from,
          to,
          text,
          time:
            Number(
              result.rows[0].time
            )
        };

        send(socket, message);

        for (
          const client
          of wss.clients
        ) {
          if (
            client.readyState ===
              WebSocket.OPEN &&
            client.username === to
          ) {
            send(
              client,
              message
            );
          }
        }

        return;
      }

    } catch (error) {
      console.error(
        "❌ Fehler:",
        error
      );

      send(socket, {
        type: "error",
        text:
          "Serverfehler."
      });
    }
  });

  socket.on("close", () => {
    if (socket.username) {
      console.log(
        `📱 ${socket.username} getrennt`
      );
    }
  });
});


setInterval(() => {

  cleanOldGroupMessages()
    .catch(error => {
      console.error(
        "❌ Aufräumfehler:",
        error.message
      );
    });

  cleanExpiredResetTokens()
    .catch(error => {
      console.error(
        "❌ Reset-Aufräumfehler:",
        error.message
      );
    });

}, 10 * 60 * 1000);


initDatabase()
  .then(() => {

    server.listen(
      PORT,
      "0.0.0.0",
      () => {

        console.log(
          `🚀 Server läuft auf Port ${PORT}`
        );

      }
    );

  })
  .catch(error => {

    console.error(
      "❌ Datenbankfehler:",
      error
    );

    process.exit(1);

  });
