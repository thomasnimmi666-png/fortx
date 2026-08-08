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
    const [salt, originalHash] = stored.split(":");

    const hash = crypto.scryptSync(
      password,
      salt,
      64
    );

    return crypto.timingSafeEqual(
      hash,
      Buffer.from(originalHash, "hex")
    );
  } catch {
    return false;
  }
}

function createResetToken() {
  return crypto.randomBytes(32).toString("hex");
}

function normalizeUsername(username) {
  return String(username || "")
    .trim()
    .toLowerCase();
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      profile_image TEXT,
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
    CREATE TABLE IF NOT EXISTS password_resets (
      token_hash TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      used BOOLEAN DEFAULT FALSE
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS friendships (
      id SERIAL PRIMARY KEY,
      requester TEXT NOT NULL,
      receiver TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(requester, receiver)
    )
  `);

  // Falls die users-Tabelle bereits existiert und profile_image noch fehlt.
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS profile_image TEXT
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

async function sendFriends(socket) {
  if (!socket.username) {
    return;
  }

  const username = socket.username;

  const result = await pool.query(
    `
    SELECT
      u.username,
      u.profile_image
    FROM friendships f
    JOIN users u
      ON (
        CASE
          WHEN f.requester = $1
          THEN u.username = f.receiver
          ELSE u.username = f.requester
        END
      )
    WHERE
      (
        f.requester = $1
        OR f.receiver = $1
      )
      AND f.status = 'accepted'
    ORDER BY u.username ASC
    `,
    [username]
  );

  send(socket, {
    type: "friends",
    friends: result.rows
  });
}

async function notifyFriendRequest(receiverUsername, requesterUsername) {
  for (const client of wss.clients) {
    if (
      client.readyState === WebSocket.OPEN &&
      client.username === receiverUsername
    ) {
      send(client, {
        type: "friendRequest",
        from: requesterUsername
      });

      await sendFriendRequests(client);
    }
  }
}

async function sendFriendRequests(socket) {
  if (!socket.username) {
    return;
  }

  const result = await pool.query(
    `
    SELECT requester
    FROM friendships
    WHERE receiver = $1
      AND status = 'pending'
    ORDER BY created_at ASC
    `,
    [socket.username]
  );

  send(socket, {
    type: "friendRequests",
    requests: result.rows
  });
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
    "Content-Type": "text/plain; charset=utf-8"
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
      const data = JSON.parse(raw.toString());

      /*
       * REGISTRIERUNG
       */

      if (data.type === "register") {
        const username = normalizeUsername(
          data.username
        );

        const password =
          String(data.password || "");

        const accessCode =
          String(data.accessCode || "");

        if (!ACCESS_CODE) {
          send(socket, {
            type: "error",
            text: "Server-Zugangscode fehlt."
          });
          return;
        }

        if (accessCode !== ACCESS_CODE) {
          send(socket, {
            type: "error",
            text: "Falscher Zugangscode."
          });
          return;
        }

        if (
          username.length < 3 ||
          password.length < 8
        ) {
          send(socket, {
            type: "error",
            text:
              "Benutzername mindestens 3 Zeichen und Passwort mindestens 8 Zeichen."
          });
          return;
        }

        const existing = await pool.query(
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

        await sendFriends(socket);
        await sendFriendRequests(socket);

        console.log(
          `👤 Registriert: ${username}`
        );

        return;
      }

      /*
       * LOGIN
       */

      if (data.type === "login") {
        const username = normalizeUsername(
          data.username
        );

        const password =
          String(data.password || "");

        const result = await pool.query(
          `
          SELECT
            username,
            password_hash,
            profile_image
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
          username,
          profileImage:
            result.rows[0].profile_image || ""
        });

        await sendFriends(socket);
        await sendFriendRequests(socket);

        console.log(
          `🔓 Login: ${username}`
        );

        return;
      }

      /*
       * PROFILBILD SPEICHERN
       */

      if (data.type === "saveProfileImage") {
        if (!socket.username) {
          return;
        }

        const image =
          String(data.image || "");

        if (image.length > 5_000_000) {
          send(socket, {
            type: "error",
            text:
              "Das Profilbild ist zu groß."
          });
          return;
        }

        await pool.query(
          `
          UPDATE users
          SET profile_image = $1
          WHERE username = $2
          `,
          [
            image,
            socket.username
          ]
        );

        send(socket, {
          type: "profileImageSaved",
          image
        });

        return;
      }

      /*
       * FREUND HINZUFÜGEN
       */

      if (data.type === "addFriend") {
        if (!socket.username) {
          return;
        }

        const requester =
          socket.username;

        const receiver =
          normalizeUsername(data.username);

        if (!receiver) {
          send(socket, {
            type: "error",
            text:
              "Bitte einen Benutzernamen eingeben."
          });
          return;
        }

        if (requester === receiver) {
          send(socket, {
            type: "error",
            text:
              "Du kannst dich nicht selbst hinzufügen."
          });
          return;
        }

        const userResult =
          await pool.query(
            `
            SELECT username
            FROM users
            WHERE username = $1
            `,
            [receiver]
          );

        if (userResult.rows.length === 0) {
          send(socket, {
            type: "error",
            text:
              "Benutzer nicht gefunden."
          });
          return;
        }

        const existing =
          await pool.query(
            `
            SELECT *
            FROM friendships
            WHERE
              (
                requester = $1
                AND receiver = $2
              )
              OR
              (
                requester = $2
                AND receiver = $1
              )
            LIMIT 1
            `,
            [
              requester,
              receiver
            ]
          );

        if (existing.rows.length > 0) {
          const friendship =
            existing.rows[0];

          if (
            friendship.status ===
            "accepted"
          ) {
            send(socket, {
              type: "error",
              text:
                "Ihr seid bereits befreundet."
            });
            return;
          }

          if (
            friendship.status ===
              "pending" &&
            friendship.receiver ===
              requester
          ) {
            await pool.query(
              `
              UPDATE friendships
              SET status = 'accepted'
              WHERE id = $1
              `,
              [friendship.id]
            );

            send(socket, {
              type: "friendAccepted",
              username: receiver
            });

            await sendFriends(socket);

            for (const client of wss.clients) {
              if (
                client.readyState ===
                  WebSocket.OPEN &&
                client.username ===
                  friendship.requester
              ) {
                send(client, {
                  type: "friendAccepted",
                  username: requester
                });

                await sendFriends(client);
              }
            }

            return;
          }

          send(socket, {
            type: "error",
            text:
              "Eine Freundschaftsanfrage existiert bereits."
          });

          return;
        }

        await pool.query(
          `
          INSERT INTO friendships
          (requester, receiver, status)
          VALUES ($1, $2, 'pending')
          `,
          [
            requester,
            receiver
          ]
        );

        send(socket, {
          type: "requestSent",
          to: receiver
        });

        await notifyFriendRequest(
          receiver,
          requester
        );

        console.log(
          `👥 Freundschaftsanfrage: ${requester} -> ${receiver}`
        );

        return;
      }

      /*
       * FREUNDSCHAFTSANFRAGE ANNEHMEN
       */

      if (data.type === "acceptFriend") {
        if (!socket.username) {
          return;
        }

        const requester =
          normalizeUsername(
            data.username
          );

        const receiver =
          socket.username;

        const result =
          await pool.query(
            `
            UPDATE friendships
            SET status = 'accepted'
            WHERE requester = $1
              AND receiver = $2
              AND status = 'pending'
            RETURNING *
            `,
            [
              requester,
              receiver
            ]
          );

        if (result.rows.length === 0) {
          send(socket, {
            type: "error",
            text:
              "Freundschaftsanfrage nicht gefunden."
          });
          return;
        }

        send(socket, {
          type: "friendAccepted",
          username: requester
        });

        await sendFriends(socket);
        await sendFriendRequests(socket);

        for (const client of wss.clients) {
          if (
            client.readyState === WebSocket.OPEN &&
            client.username === requester
          ) {
            send(client, {
              type: "friendAccepted",
              username: receiver
            });

            await sendFriends(client);
          }
        }

        return;
      }

      /*
       * FREUNDSCHAFTSANFRAGEN LADEN
       */

      if (data.type === "getFriendRequests") {
        if (!socket.username) {
          return;
        }

        await sendFriendRequests(socket);
        return;
      }

      /*
       * FREUNDE LADEN
       */

      if (data.type === "getFriends") {
        if (!socket.username) {
          return;
        }

        await sendFriends(socket);
        return;
      }

      /*
       * PASSWORT VERGESSEN
       */

      if (data.type === "forgotPassword") {
        const username =
          normalizeUsername(
            data.username
          );

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
            type: "forgotPasswordSent",
            text:
              "Wenn das Konto existiert, wurde eine Anfrage an die Admins gesendet."
          });
          return;
        }

        const requestId =
          crypto.randomBytes(16).toString("hex");

        for (const client of wss.clients) {
          if (
            client.readyState === WebSocket.OPEN &&
            client.username &&
            GROUP_ADMINS.includes(
              client.username
            )
          ) {
            send(client, {
              type: "passwordResetRequest",
              requestId,
              username,
              time: Date.now()
            });
          }
        }

        send(socket, {
          type: "forgotPasswordSent",
          text:
            "Die Anfrage wurde an die Admins gesendet."
        });

        return;
      }

      /*
       * RESET-LINK ERSTELLEN
       */

      if (data.type === "createPasswordReset") {
        const admin =
          socket.username;

        if (
          !admin ||
          !GROUP_ADMINS.includes(admin)
        ) {
          send(socket, {
            type: "error",
            text:
              "Nur Admins dürfen Reset-Links erstellen."
          });
          return;
        }

        const username =
          normalizeUsername(
            data.username
          );

        if (!username) {
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
          (token_hash, username, expires_at)
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

        return;
      }

      /*
       * PASSWORT ZURÜCKSETZEN
       */

      if (data.type === "resetPassword") {
        const token =
          String(data.token || "");

        const newPassword =
          String(data.password || "");

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
            hashPassword(newPassword),
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
          await pool.query(`
            SELECT
              sender AS username,
              text,
              EXTRACT(EPOCH FROM created_at) * 1000 AS time
            FROM messages
            WHERE is_group = TRUE
            ORDER BY created_at ASC
          `);

        send(socket, {
          type: "groupMessages",
          messages: result.rows
        });

        return;
      }

      /*
       * GRUPPENNACHRICHT
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

        if (
          !GROUP_ADMINS.includes(
            username
          )
        ) {
          send(socket, {
            type: "error",
            text:
              "Du darfst im Gruppenchat nur lesen."
          });
          return;
        }

        const text =
          String(data.text || "")
            .trim();

        if (!text) {
          return;
        }

        const result =
          await pool.query(
            `
            INSERT INTO messages
            (sender, text, is_group)
            VALUES ($1, $2, TRUE)
            RETURNING
              sender,
              text,
              EXTRACT(EPOCH FROM created_at) * 1000 AS time
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
            Number(result.rows[0].time)
        };

        await broadcastGroup({
          type: "groupMessage",
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
          normalizeUsername(
            data.to
          );

        const text =
          String(data.text || "")
            .trim();

        if (!from || !to || !text) {
          return;
        }

        const friendship =
          await pool.query(
            `
            SELECT id
            FROM friendships
            WHERE status = 'accepted'
              AND (
                (
                  requester = $1
                  AND receiver = $2
                )
                OR
                (
                  requester = $2
                  AND receiver = $1
                )
              )
            LIMIT 1
            `,
            [
              from,
              to
            ]
          );

        if (friendship.rows.length === 0) {
          send(socket, {
            type: "error",
            text:
              "Du kannst diesem Benutzer erst schreiben, wenn ihr befreundet seid."
          });
          return;
        }

        await pool.query(
          `
          INSERT INTO messages
          (sender, receiver, text, is_group)
          VALUES ($1, $2, $3, FALSE)
          `,
          [
            from,
            to,
            text
          ]
        );

        send(socket, {
          type: "message",
          from,
          to,
          text
        });

        for (const client of wss.clients) {
          if (
            client.readyState === WebSocket.OPEN &&
            client.username === to
          ) {
            send(client, {
              type: "message",
              from,
              to,
              text
            });
          }
        }

        return;
      }

    } catch (error) {
      console.log(
        "❌ Fehler:",
        error.message
      );

      send(socket, {
        type: "error",
        text: "Serverfehler."
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
      console.log(
        "❌ Aufräumfehler:",
        error.message
      );
    });

  cleanExpiredResetTokens()
    .catch(error => {
      console.log(
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
