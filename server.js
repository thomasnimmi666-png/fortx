const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const WebSocket = require("ws");
const { Pool } = require("pg");

const PORT = process.env.PORT || 3000;
const ACCESS_CODE = process.env.ACCESS_CODE || "";
const APP_URL = process.env.APP_URL || "";

const GROUP_ADMINS = [
  "saftpresse040",
  "thcliquide"
];

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

const uploadDir = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

function isAdmin(username) {
  return GROUP_ADMINS.includes(
    String(username || "").trim().toLowerCase()
  );
}

function send(socket, data) {
  if (socket?.readyState === WebSocket.OPEN) {
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

    const original = Buffer.from(
      originalHash,
      "hex"
    );

    return (
      hash.length === original.length &&
      crypto.timingSafeEqual(hash, original)
    );
  } catch {
    return false;
  }
}

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
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
    CREATE TABLE IF NOT EXISTS friends (
      username TEXT NOT NULL
        REFERENCES users(username)
        ON DELETE CASCADE,

      friend_username TEXT NOT NULL
        REFERENCES users(username)
        ON DELETE CASCADE,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

      PRIMARY KEY (username, friend_username)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender TEXT NOT NULL,
      receiver TEXT,
      text TEXT,
      image_url TEXT,
      is_group BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS image_url TEXT
  `);

  await pool.query(`
    ALTER TABLE messages
    ALTER COLUMN text DROP NOT NULL
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_resets (
      token_hash TEXT PRIMARY KEY,

      username TEXT NOT NULL
        REFERENCES users(username)
        ON DELETE CASCADE,

      expires_at TIMESTAMP NOT NULL,

      used BOOLEAN DEFAULT FALSE
    )
  `);

  console.log("🗄️ Datenbank bereit");
}

async function addDefaultAdmins(username) {
  for (const admin of GROUP_ADMINS) {
    if (admin === username) continue;

    const exists = await pool.query(
      `
      SELECT 1
      FROM users
      WHERE username = $1
      `,
      [admin]
    );

    if (exists.rowCount) {
      await pool.query(
        `
        INSERT INTO friends
        (username, friend_username)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        `,
        [username, admin]
      );
    }
  }
}

async function addUserToAllAdminContacts(username) {
  for (const admin of GROUP_ADMINS) {
    const adminExists = await pool.query(
      `
      SELECT 1
      FROM users
      WHERE username = $1
      `,
      [admin]
    );

    if (adminExists.rowCount) {
      await pool.query(
        `
        INSERT INTO friends
        (username, friend_username)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        `,
        [username, admin]
      );

      await pool.query(
        `
        INSERT INTO friends
        (username, friend_username)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        `,
        [admin, username]
      );
    }
  }
}

async function cleanOldGroupMessages() {
  await pool.query(`
    DELETE FROM messages
    WHERE is_group = TRUE
    AND created_at < NOW() - INTERVAL '24 hours'
  `);
}

async function cleanResetTokens() {
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

function getFile(reqUrl) {
  let requested = reqUrl.split("?")[0];

  if (requested === "/" || requested === "") {
    requested = "/index.html";
  }

  const file = path.normalize(
    path.join(__dirname, requested)
  );

  const root = path.normalize(__dirname);

  if (!file.startsWith(root)) {
    return null;
  }

  return file;
}

const server = http.createServer(
  (req, res) => {
    if (req.url === "/health") {
      res.writeHead(200, {
        "Content-Type":
          "application/json"
      });

      res.end(
        JSON.stringify({
          status: "ok"
        })
      );

      return;
    }

    const file = getFile(req.url || "/");

    if (!file) {
      res.writeHead(403);
      res.end("Forbidden");
      return;
    }

    const ext = path.extname(file);

    const types = {
      ".html":
        "text/html; charset=utf-8",
      ".js":
        "application/javascript; charset=utf-8",
      ".css":
        "text/css; charset=utf-8",
      ".json":
        "application/json; charset=utf-8",
      ".png":
        "image/png",
      ".jpg":
        "image/jpeg",
      ".jpeg":
        "image/jpeg",
      ".webp":
        "image/webp",
      ".svg":
        "image/svg+xml",
      ".ico":
        "image/x-icon"
    };

    fs.readFile(
      file,
      (error, data) => {
        if (error) {
          res.writeHead(404);
          res.end("Datei nicht gefunden");
          return;
        }

        res.writeHead(200, {
          "Content-Type":
            types[ext] ||
            "application/octet-stream"
        });

        res.end(data);
      }
    );
  }
);

const wss = new WebSocket.Server({
  server
});

wss.on("connection", socket => {
  console.log("📱 Gerät verbunden");

  socket.on("message", async raw => {
    try {
      const data = JSON.parse(
        raw.toString()
      );

      /*
       * REGISTER
       */

      if (data.type === "register") {
        const username = String(
          data.username || ""
        )
          .trim()
          .toLowerCase();

        const password = String(
          data.password || ""
        );

        const accessCode = String(
          data.accessCode || ""
        );

        if (!ACCESS_CODE) {
          send(socket, {
            type: "error",
            text:
              "ACCESS_CODE fehlt auf Render."
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
          !/^[a-z0-9_]{3,30}$/.test(
            username
          )
        ) {
          send(socket, {
            type: "error",
            text:
              "Benutzername: 3–30 Zeichen."
          });
          return;
        }

        if (password.length < 8) {
          send(socket, {
            type: "error",
            text:
              "Passwort muss mindestens 8 Zeichen haben."
          });
          return;
        }

        const exists = await pool.query(
          `
          SELECT 1
          FROM users
          WHERE username = $1
          `,
          [username]
        );

        if (exists.rowCount) {
          send(socket, {
            type: "error",
            text:
              "Benutzername bereits vergeben."
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

        await addUserToAllAdminContacts(
          username
        );

        await addDefaultAdmins(username);

        socket.username = username;

        send(socket, {
          type: "registered",
          username,
          isAdmin: isAdmin(username)
        });

        return;
      }

      /*
       * LOGIN
       */

      if (data.type === "login") {
        const username = String(
          data.username || ""
        )
          .trim()
          .toLowerCase();

        const password = String(
          data.password || ""
        );

        const result = await pool.query(
          `
          SELECT username, password_hash
          FROM users
          WHERE username = $1
          `,
          [username]
        );

        if (
          !result.rowCount ||
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

        await addUserToAllAdminContacts(
          username
        );

        await addDefaultAdmins(username);

        socket.username = username;

        send(socket, {
          type: "loggedIn",
          username,
          isAdmin: isAdmin(username)
        });

        return;
      }

      /*
       * GET USERS
       * Für Admins
       */

      if (data.type === "getUsers") {
        if (!socket.username || !isAdmin(socket.username)) {
          return;
        }

        const result = await pool.query(`
          SELECT
            username,
            created_at
          FROM users
          ORDER BY username
        `);

        send(socket, {
          type: "users",
          users: result.rows
        });

        return;
      }

      /*
       * FORGOT PASSWORD
       */

      if (data.type === "forgotPassword") {
        const username = String(
          data.username || ""
        )
          .trim()
          .toLowerCase();

        if (!username) {
          send(socket, {
            type: "error",
            text:
              "Bitte Benutzername eingeben."
          });
          return;
        }

        const result = await pool.query(
          `
          SELECT username
          FROM users
          WHERE username = $1
          `,
          [username]
        );

        send(socket, {
          type:
            "forgotPasswordSent",
          text:
            "Wenn das Konto existiert, wurde eine Anfrage an die Admins gesendet."
        });

        if (!result.rowCount) {
          return;
        }

        for (const client of wss.clients) {
          if (
            client.readyState ===
              WebSocket.OPEN &&
            client.username &&
            isAdmin(client.username)
          ) {
            send(client, {
              type:
                "passwordResetRequest",
              username,
              time: Date.now()
            });
          }
        }

        return;
      }

      /*
       * CREATE RESET LINK
       */

      if (
        data.type ===
        "createPasswordReset"
      ) {
        if (
          !socket.username ||
          !isAdmin(socket.username)
        ) {
          send(socket, {
            type: "error",
            text:
              "Nur Admins dürfen Reset-Links erstellen."
          });
          return;
        }

        const username = String(
          data.username || ""
        )
          .trim()
          .toLowerCase();

        const user = await pool.query(
          `
          SELECT username
          FROM users
          WHERE username = $1
          `,
          [username]
        );

        if (!user.rowCount) {
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

        const token = crypto
          .randomBytes(32)
          .toString("hex");

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
            hashToken(token),
            username
          ]
        );

        const baseUrl =
          APP_URL ||
          `https://${
            process.env
              .RENDER_EXTERNAL_HOSTNAME ||
            "localhost"
          }`;

        send(socket, {
          type:
            "passwordResetLink",
          username,
          resetUrl:
            `${baseUrl}/?reset=${token}`,
          expiresIn:
            15 * 60 * 1000
        });

        return;
      }

      /*
       * RESET PASSWORD
       */

      if (
        data.type ===
        "resetPassword"
      ) {
        const token = String(
          data.token || ""
        );

        const password = String(
          data.password || ""
        );

        if (
          !token ||
          password.length < 8
        ) {
          send(socket, {
            type: "error",
            text:
              "Das neue Passwort muss mindestens 8 Zeichen haben."
          });
          return;
        }

        const result = await pool.query(
          `
          SELECT username
          FROM password_resets
          WHERE token_hash = $1
          AND used = FALSE
          AND expires_at > NOW()
          `,
          [hashToken(token)]
        );

        if (!result.rowCount) {
          send(socket, {
            type: "error",
            text:
              "Reset-Link ungültig oder abgelaufen."
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
            hashPassword(password),
            username
          ]
        );

        await pool.query(
          `
          UPDATE password_resets
          SET used = TRUE
          WHERE token_hash = $1
          `,
          [hashToken(token)]
        );

        send(socket, {
          type:
            "passwordResetSuccess",
          username
        });

        return;
      }

      /*
       * FRIENDS
       */

      if (data.type === "getFriends") {
        if (!socket.username) return;

        await addUserToAllAdminContacts(
          socket.username
        );

        await addDefaultAdmins(
          socket.username
        );

        const result = await pool.query(
          `
          SELECT friend_username AS username
          FROM friends
          WHERE username = $1
          ORDER BY friend_username
          `,
          [socket.username]
        );

        send(socket, {
          type: "friends",
          friends: result.rows.map(
            row => row.username
          )
        });

        return;
      }

      /*
       * ADD FRIEND
       */

      if (data.type === "addFriend") {
        if (!socket.username) return;

        const friend = String(
          data.username || ""
        )
          .trim()
          .toLowerCase();

        if (
          !friend ||
          friend === socket.username
        ) {
          send(socket, {
            type: "error",
            text:
              "Ungültiger Benutzer."
          });
          return;
        }

        const user = await pool.query(
          `
          SELECT 1
          FROM users
          WHERE username = $1
          `,
          [friend]
        );

        if (!user.rowCount) {
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
            socket.username,
            friend
          ]
        );

        send(socket, {
          type: "friendAdded",
          username: friend
        });

        return;
      }

      /*
       * PRIVATE MESSAGES
       */

      if (
        data.type ===
        "getPrivateMessages"
      ) {
        if (!socket.username) return;

        const other = String(
          data.username || ""
        )
          .trim()
          .toLowerCase();

        const result = await pool.query(
          `
          SELECT
            sender AS "from",
            receiver AS "to",
            text,
            image_url AS "imageUrl",
            EXTRACT(
              EPOCH FROM created_at
            ) * 1000 AS time
          FROM messages
          WHERE is_group = FALSE
          AND (
            (
              sender = $1
              AND receiver = $2
            )
            OR
            (
              sender = $2
              AND receiver = $1
            )
          )
          ORDER BY created_at ASC
          `,
          [
            socket.username,
            other
          ]
        );

        send(socket, {
          type:
            "privateMessages",
          username: other,
          messages: result.rows.map(
            row => ({
              ...row,
              time: Number(row.time)
            })
          )
        });

        return;
      }

      /*
       * GROUP MESSAGES
       */

      if (
        data.type ===
        "getGroupMessages"
      ) {
        if (!socket.username) return;

        await cleanOldGroupMessages();

        const result = await pool.query(
          `
          SELECT
            sender AS username,
            text,
            image_url AS "imageUrl",
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
          messages: result.rows.map(
            row => ({
              ...row,
              time: Number(row.time)
            })
          )
        });

        return;
      }

      /*
       * GROUP MESSAGE
       */

      if (
        data.type ===
        "groupMessage"
      ) {
        const username =
          socket.username;

        if (!username) return;

        if (!isAdmin(username)) {
          send(socket, {
            type: "error",
            text:
              "Du darfst im Gruppenchat nur lesen."
          });
          return;
        }

        const text = String(
          data.text || ""
        ).trim();

        const imageUrl =
          data.imageUrl || null;

        if (!text && !imageUrl) return;

        const result = await pool.query(
          `
          INSERT INTO messages
          (
            sender,
            text,
            image_url,
            is_group
          )
          VALUES ($1,$2,$3,TRUE)
          RETURNING
            sender,
            text,
            image_url AS "imageUrl",
            EXTRACT(
              EPOCH FROM created_at
            ) * 1000 AS time
          `,
          [
            username,
            text || null,
            imageUrl
          ]
        );

        const message = {
          username:
            result.rows[0].sender,
          text:
            result.rows[0].text,
          imageUrl:
            result.rows[0].imageUrl,
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
       * PRIVATE MESSAGE
       */

      if (data.type === "message") {
        const from =
          socket.username;

        const to = String(
          data.to || ""
        )
          .trim()
          .toLowerCase();

        const text = String(
          data.text || ""
        ).trim();

        const imageUrl =
          data.imageUrl || null;

        if (!from || !to) return;

        if (!text && !imageUrl) return;

        const target = await pool.query(
          `
          SELECT 1
          FROM users
          WHERE username = $1
          `,
          [to]
        );

        if (!target.rowCount) {
          send(socket, {
            type: "error",
            text:
              "Benutzer nicht gefunden."
          });
          return;
        }

        const result = await pool.query(
          `
          INSERT INTO messages
          (
            sender,
            receiver,
            text,
            image_url,
            is_group
          )
          VALUES ($1,$2,$3,$4,FALSE)
          RETURNING
            EXTRACT(
              EPOCH FROM created_at
            ) * 1000 AS time
          `,
          [
            from,
            to,
            text || null,
            imageUrl
          ]
        );

        const message = {
          type: "message",
          from,
          to,
          text,
          imageUrl,
          time:
            Number(
              result.rows[0].time
            )
        };

        send(socket, message);

        for (const client of wss.clients) {
          if (
            client.readyState ===
              WebSocket.OPEN &&
            client.username === to
          ) {
            send(client, message);
          }
        }

        return;
      }

      /*
       * IMAGE UPLOAD
       *
       * Das Frontend schickt ein
       * kleines Bild als Base64.
       */

      if (data.type === "uploadImage") {
        if (!socket.username) return;

        const image = String(
          data.image || ""
        );

        const match =
          image.match(
            /^data:(image\/(?:png|jpeg|jpg|webp|gif));base64,(.+)$/
          );

        if (!match) {
          send(socket, {
            type: "error",
            text:
              "Ungültiges Bild."
          });
          return;
        }

        const mime = match[1];
        const base64 = match[2];

        const buffer =
          Buffer.from(
            base64,
            "base64"
          );

        if (buffer.length > 8 * 1024 * 1024) {
          send(socket, {
            type: "error",
            text:
              "Bild darf maximal 8 MB groß sein."
          });
          return;
        }

        const extension =
          mime.includes("png")
            ? "png"
            : mime.includes("webp")
            ? "webp"
            : mime.includes("gif")
            ? "gif"
            : "jpg";

        const filename =
          `${Date.now()}-${crypto
            .randomBytes(8)
            .toString("hex")}.${extension}`;

        fs.writeFileSync(
          path.join(
            uploadDir,
            filename
          ),
          buffer
        );

        const baseUrl =
          APP_URL ||
          `https://${
            process.env
              .RENDER_EXTERNAL_HOSTNAME ||
            "localhost"
          }`;

        send(socket, {
          type: "imageUploaded",
          url:
            `${baseUrl}/uploads/${filename}`
        });

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
          "Serverfehler: " +
          error.message
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
  cleanOldGroupMessages().catch(
    error =>
      console.error(
        "Gruppenchat:",
        error.message
      )
  );

  cleanResetTokens().catch(
    error =>
      console.error(
        "Reset:",
        error.message
      )
  );
}, 10 * 60 * 1000);

initDatabase()
  .then(() => {
    server.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `🚀 FORTX läuft auf Port ${PORT}`
        );

        console.log(
          "👑 Admins:",
          GROUP_ADMINS.join(", ")
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
