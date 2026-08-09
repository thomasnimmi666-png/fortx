const http = require("http");
const path = require("path");
const fs = require("fs");
const WebSocket = require("ws");
const crypto = require("crypto");
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

function send(socket, data) {
  if (
    socket &&
    socket.readyState === WebSocket.OPEN
  ) {
    socket.send(JSON.stringify(data));
  }
}

function hashPassword(password) {
  const salt =
    crypto.randomBytes(16).toString("hex");

  const hash =
    crypto.scryptSync(
      password,
      salt,
      64
    ).toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const [salt, originalHash] =
      stored.split(":");

    const hash =
      crypto.scryptSync(
        password,
        salt,
        64
      );

    const original =
      Buffer.from(
        originalHash,
        "hex"
      );

    return (
      hash.length === original.length &&
      crypto.timingSafeEqual(
        hash,
        original
      )
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

      PRIMARY KEY (
        username,
        friend_username
      )
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

      username TEXT NOT NULL
        REFERENCES users(username)
        ON DELETE CASCADE,

      expires_at TIMESTAMP NOT NULL,

      used BOOLEAN DEFAULT FALSE
    )
  `);

  console.log(
    "🗄️ Datenbank bereit"
  );
}

async function cleanOldGroupMessages() {
  await pool.query(`
    DELETE FROM messages
    WHERE is_group = TRUE
    AND created_at <
      NOW() - INTERVAL '24 hours'
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
  for (
    const client of wss.clients
  ) {
    if (
      client.readyState ===
        WebSocket.OPEN &&
      client.username
    ) {
      send(client, data);
    }
  }
}

function getFile(reqUrl) {
  let requested =
    reqUrl.split("?")[0];

  if (
    requested === "/" ||
    requested === ""
  ) {
    requested = "/index.html";
  }

  const file =
    path.normalize(
      path.join(
        __dirname,
        requested
      )
    );

  if (
    !file.startsWith(
      path.normalize(__dirname)
    )
  ) {
    return null;
  }

  return file;
}

const server =
  http.createServer(
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

      const file =
        getFile(req.url || "/");

      if (!file) {
        res.writeHead(403);
        res.end("Forbidden");
        return;
      }

      const ext =
        path.extname(file);

      const types = {
        ".html":
          "text/html; charset=utf-8",

        ".js":
          "application/javascript; charset=utf-8",

        ".json":
          "application/json; charset=utf-8",

        ".css":
          "text/css; charset=utf-8",

        ".png":
          "image/png",

        ".jpg":
          "image/jpeg",

        ".svg":
          "image/svg+xml"
      };

      fs.readFile(
        file,
        (error, data) => {

          if (error) {
            res.writeHead(404);
            res.end(
              "Datei nicht gefunden"
            );
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

const wss =
  new WebSocket.Server({
    server
  });

wss.on(
  "connection",
  socket => {

    console.log(
      "📱 Gerät verbunden"
    );

    socket.on(
      "message",
      async raw => {

        try {

          const data =
            JSON.parse(
              raw.toString()
            );

          /*
           * REGISTRIERUNG
           */

          if (
            data.type ===
            "register"
          ) {

            const username =
              String(
                data.username || ""
              )
                .trim()
                .toLowerCase();

            const password =
              String(
                data.password || ""
              );

            const accessCode =
              String(
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

            if (
              accessCode !==
              ACCESS_CODE
            ) {

              send(socket, {
                type: "error",
                text:
                  "Falscher Zugangscode."
              });

              return;
            }

            if (
              !/^[a-z0-9_]{3,30}$/
                .test(username)
            ) {

              send(socket, {
                type: "error",
                text:
                  "Benutzername: 3–30 Zeichen."
              });

              return;
            }

            if (
              password.length < 8
            ) {

              send(socket, {
                type: "error",
                text:
                  "Passwort muss mindestens 8 Zeichen haben."
              });

              return;
            }

            const exists =
              await pool.query(
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
                hashPassword(
                  password
                )
              ]
            );

            socket.username =
              username;

            send(socket, {
              type: "registered",
              username
            });

            return;
          }

          /*
           * LOGIN
           */

          if (
            data.type ===
            "login"
          ) {

            const username =
              String(
                data.username || ""
              )
                .trim()
                .toLowerCase();

            const password =
              String(
                data.password || ""
              );

            const result =
              await pool.query(
                `
                SELECT
                  username,
                  password_hash
                FROM users
                WHERE username = $1
                `,
                [username]
              );

            if (
              !result.rowCount ||
              !verifyPassword(
                password,
                result.rows[0]
                  .password_hash
              )
            ) {

              send(socket, {
                type: "error",
                text:
                  "Benutzername oder Passwort falsch."
              });

              return;
            }

            socket.username =
              username;

            send(socket, {
              type: "loggedIn",
              username
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
                  "Bitte Benutzername eingeben."
              });

              return;
            }

            const result =
              await pool.query(
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

            if (
              !result.rowCount
            ) {
              return;
            }

            const request = {
              type:
                "passwordResetRequest",

              username,

              time:
                Date.now()
            };

            for (
              const client of
                wss.clients
            ) {

              if (
                client.readyState ===
                  WebSocket.OPEN &&
                client.username &&
                GROUP_ADMINS.includes(
                  client.username
                )
              ) {

                send(
                  client,
                  request
                );
              }
            }

            return;
          }

          /*
           * ADMIN RESET LINK
           */

          if (
            data.type ===
            "createPasswordReset"
          ) {

            const admin =
              socket.username;

            if (
              !admin ||
              !GROUP_ADMINS.includes(
                admin
              )
            ) {

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

            const token =
              crypto
                .randomBytes(32)
                .toString("hex");

            await pool.query(
              `
              INSERT INTO
              password_resets
              (
                token_hash,
                username,
                expires_at
              )
              VALUES (
                $1,
                $2,
                NOW() +
                INTERVAL '15 minutes'
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

            const resetUrl =
              `${baseUrl}/?reset=${token}`;

            send(socket, {
              type:
                "passwordResetLink",

              username,

              resetUrl,

              expiresIn:
                15 * 60 * 1000
            });

            return;
          }

          /*
           * PASSWORT ÄNDERN
           */

          if (
            data.type ===
            "resetPassword"
          ) {

            const token =
              String(
                data.token || ""
              );

            const password =
              String(
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

            const result =
              await pool.query(
                `
                SELECT username
                FROM password_resets
                WHERE token_hash = $1
                AND used = FALSE
                AND expires_at > NOW()
                `,
                [hashToken(token)]
              );

            if (
              !result.rowCount
            ) {

              send(socket, {
                type: "error",
                text:
                  "Reset-Link ungültig oder abgelaufen."
              });

              return;
            }

            const username =
              result.rows[0]
                .username;

            await pool.query(
              `
              UPDATE users
              SET password_hash = $1
              WHERE username = $2
              `,
              [
                hashPassword(
                  password
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
           * FREUND HINZUFÜGEN
           */

          if (
            data.type ===
            "addFriend"
          ) {

            if (!socket.username)
              return;

            const friend =
              String(
                data.username || ""
              )
                .trim()
                .toLowerCase();

            if (
              !friend ||
              friend ===
                socket.username
            ) {

              send(socket, {
                type: "error",
                text:
                  "Ungültiger Benutzer."
              });

              return;
            }

            const user =
              await pool.query(
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
              (
                username,
                friend_username
              )
              VALUES ($1, $2)
              ON CONFLICT DO NOTHING
              `,
              [
                socket.username,
                friend
              ]
            );

            send(socket, {
              type:
                "friendAdded",
              username:
                friend
            });

            return;
          }

          /*
           * FREUNDE LADEN
           */

          if (
            data.type ===
            "getFriends"
          ) {

            if (!socket.username)
              return;

            const result =
              await pool.query(
                `
                SELECT
                  friend_username
                  AS username
                FROM friends
                WHERE username = $1
                ORDER BY friend_username
                `,
                [socket.username]
              );

            send(socket, {
              type: "friends",

              friends:
                result.rows.map(
                  row =>
                    row.username
                )
            });

            return;
          }

          /*
           * PRIVATE NACHRICHTEN LADEN
           */

          if (
            data.type ===
            "getPrivateMessages"
          ) {

            if (!socket.username)
              return;

            const other =
              String(
                data.username || ""
              )
                .trim()
                .toLowerCase();

            const result =
              await pool.query(
                `
                SELECT
                  sender AS "from",
                  receiver AS "to",
                  text,
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

              username:
                other,

              messages:
                result.rows.map(
                  row => ({
                    ...row,
                    time:
                      Number(
                        row.time
                      )
                  })
                )
            });

            return;
          }

          /*
           * ALLGEMEIN LADEN
           */

          if (
            data.type ===
            "getGroupMessages"
          ) {

            if (!socket.username)
              return;

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
                    ...row,
                    time:
                      Number(
                        row.time
                      )
                  })
                )
            });

            return;
          }

          /*
           * ALLGEMEIN NACHRICHT
           */

          if (
            data.type ===
            "groupMessage"
          ) {

            const username =
              socket.username;

            if (!username)
              return;

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
              String(
                data.text || ""
              ).trim();

            if (!text)
              return;

            const result =
              await pool.query(
                `
                INSERT INTO messages
                (
                  sender,
                  text,
                  is_group
                )
                VALUES ($1,$2,TRUE)

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
                result.rows[0]
                  .sender,

              text:
                result.rows[0]
                  .text,

              time:
                Number(
                  result.rows[0]
                    .time
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

            const target =
              await pool.query(
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
                  $1,$2,$3,FALSE
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
              type: "message",

              from,

              to,

              text,

              time:
                Number(
                  result.rows[0]
                    .time
                )
            };

            send(
              socket,
              message
            );

            for (
              const client of
                wss.clients
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
              "Serverfehler: " +
              error.message
          });
        }
      }
    );

    socket.on(
      "close",
      () => {

        if (
          socket.username
        ) {

          console.log(
            `📱 ${socket.username} getrennt`
          );
        }
      }
    );
  }
);

setInterval(
  () => {

    cleanOldGroupMessages()
      .catch(error =>
        console.error(
          error.message
        )
      );

    cleanResetTokens()
      .catch(error =>
        console.error(
          error.message
        )
      );

  },
  10 * 60 * 1000
);

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
