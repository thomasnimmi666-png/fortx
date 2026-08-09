```js
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

function isAdmin(username) {
  return GROUP_ADMINS.includes(
    String(username || "").trim().toLowerCase()
  );
}

/* =========================
   DATENBANK
========================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

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
      username TEXT NOT NULL,
      friend_username TEXT NOT NULL,
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
    CREATE TABLE IF NOT EXISTS password_resets (
      token_hash TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      used BOOLEAN DEFAULT FALSE
    )
  `);

  /*
   * Falls die messages-Tabelle aus einer älteren Version stammt,
   * werden fehlende Spalten nachträglich hinzugefügt.
   */

  await pool.query(`
    ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS image_url TEXT
  `);

  /*
   * Alte Freunde-Tabelle reparieren, falls sie aus einer
   * früheren Version stammt.
   */

  await pool.query(`
    ALTER TABLE friends
    ADD COLUMN IF NOT EXISTS username TEXT
  `);

  await pool.query(`
    ALTER TABLE friends
    ADD COLUMN IF NOT EXISTS friend_username TEXT
  `);

  console.log("🗄️ Datenbank bereit");
}

/* =========================
   PASSWORT
========================= */

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const parts = String(stored).split(":");

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

    const original = Buffer.from(
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

/* =========================
   WEBSOCKET
========================= */

let wss;

function send(socket, data) {
  if (
    socket &&
    socket.readyState === WebSocket.OPEN
  ) {
    socket.send(JSON.stringify(data));
  }
}

function broadcastGroup(data) {
  if (!wss) return;

  for (const client of wss.clients) {
    if (
      client.readyState === WebSocket.OPEN &&
      client.username
    ) {
      send(client, data);
    }
  }
}

/* =========================
   AUTOMATISCHE KONTAKTE
========================= */

async function addDefaultAdmins(username) {
  if (!username) return;

  for (const admin of GROUP_ADMINS) {
    if (admin === username) continue;

    await pool.query(
      `
      INSERT INTO friends
      (username, friend_username)
      VALUES ($1, $2)
      ON CONFLICT DO NOTHING
      `,
      [
        username,
        admin
      ]
    );

    /*
     * Auch der Admin bekommt den neuen Benutzer
     * automatisch als Kontakt.
     */

    await pool.query(
      `
      INSERT INTO friends
      (username, friend_username)
      VALUES ($1, $2)
      ON CONFLICT DO NOTHING
      `,
      [
        admin,
        username
      ]
    );
  }
}

/* =========================
   DATEIEN
========================= */

function getFile(reqUrl) {
  let requested = String(reqUrl || "/")
    .split("?")[0];

  if (
    requested === "/" ||
    requested === ""
  ) {
    requested = "/index.html";
  }

  const base = path.resolve(__dirname);

  const file = path.resolve(
    path.join(__dirname, requested)
  );

  if (
    file !== base &&
    !file.startsWith(base + path.sep)
  ) {
    return null;
  }

  return file;
}

const server = http.createServer(
  (req, res) => {
    if (req.url === "/health") {
      res.writeHead(200, {
        "Content-Type":
          "application/json; charset=utf-8"
      });

      res.end(
        JSON.stringify({
          status: "ok"
        })
      );

      return;
    }

    const file = getFile(req.url);

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

      ".gif":
        "image/gif",

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

/* =========================
   WEBSOCKET SERVER
========================= */

wss = new WebSocket.Server({
  server
});

wss.on(
  "connection",
  socket => {
    console.log("📱 Gerät verbunden");

    socket.on(
      "message",
      async raw => {
        try {
          const data = JSON.parse(
            raw.toString()
          );

          /* =========================
             REGISTER
          ========================= */

          if (
            data.type === "register"
          ) {
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
                  "ACCESS_CODE ist auf dem Server nicht eingerichtet."
              });

              return;
            }

            if (
              accessCode !== ACCESS_CODE
            ) {
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
                  "Benutzername muss 3–30 Zeichen haben."
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
                SELECT username
                FROM users
                WHERE username = $1
                `,
                [username]
              );

            if (exists.rowCount > 0) {
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

            /*
             * Neuer Benutzer bekommt automatisch
             * beide Admins als Kontakte.
             */

            await addDefaultAdmins(
              username
            );

            socket.username =
              username;

            send(socket, {
              type: "registered",
              username,
              isAdmin:
                isAdmin(username)
            });

            return;
          }

          /* =========================
             LOGIN
          ========================= */

          if (
            data.type === "login"
          ) {
            const username = String(
              data.username || ""
            )
              .trim()
              .toLowerCase();

            const password = String(
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

            /*
             * Falls der Benutzer schon existiert,
             * aber noch keine Admin-Kontakte hat,
             * werden sie hier nachgetragen.
             */

            await addDefaultAdmins(
              username
            );

            socket.username =
              username;

            send(socket, {
              type: "loggedIn",
              username,
              isAdmin:
                isAdmin(username)
            });

            return;
          }

          /* =========================
             FORGOT PASSWORD
          ========================= */

          if (
            data.type ===
            "forgotPassword"
          ) {
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

            if (!result.rowCount) {
              return;
            }

            for (
              const client of wss.clients
            ) {
              if (
                client.readyState ===
                  WebSocket.OPEN &&
                client.username &&
                isAdmin(
                  client.username
                )
              ) {
                send(client, {
                  type:
                    "passwordResetRequest",
                  username,
                  time:
                    Date.now()
                });
              }
            }

            return;
          }

          /* =========================
             ADMIN RESET LINK
          ========================= */

          if (
            data.type ===
            "createPasswordReset"
          ) {
            if (
              !isAdmin(
                socket.username
              )
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
              crypto.randomBytes(32)
                .toString("hex");

            await pool.query(
              `
              INSERT INTO password_resets
              (
                token_hash,
                username,
                expires_at,
                used
              )
              VALUES
              (
                $1,
                $2,
                NOW() + INTERVAL '15 minutes',
                FALSE
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

          /* =========================
             RESET PASSWORD
          ========================= */

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

            if (!result.rowCount) {
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

          /* =========================
             GET FRIENDS
          ========================= */

          if (
            data.type ===
            "getFriends"
          ) {
            if (!socket.username) {
              return;
            }

            /*
             * Sicherstellen, dass die Admins
             * immer vorhanden sind.
             */

            await addDefaultAdmins(
              socket.username
            );

            const result =
              await pool.query(
                `
                SELECT
                  friend_username AS username
                FROM friends
                WHERE username = $1
                ORDER BY friend_username ASC
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

          /* =========================
             ADD FRIEND
          ========================= */

          if (
            data.type ===
            "addFriend"
          ) {
            if (!socket.username) {
              return;
            }

            const friend = String(
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
                SELECT username
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

            /*
             * Freundschaft auch rückwärts
             * eintragen.
             */

            await pool.query(
              `
              INSERT INTO friends
              (username, friend_username)
              VALUES ($1, $2)
              ON CONFLICT DO NOTHING
              `,
              [
                friend,
                socket.username
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

          /* =========================
             PRIVATE MESSAGES LADEN
          ========================= */

          if (
            data.type ===
            "getPrivateMessages"
          ) {
            if (!socket.username) {
              return;
            }

            const other = String(
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
                  image_url AS "imageUrl",
                  EXTRACT(
                    EPOCH FROM created_at
                  ) * 1000 AS time
                FROM messages
                WHERE is_group = FALSE
                AND
                (
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

          /* =========================
             ALLGEMEIN LADEN
          ========================= */

          if (
            data.type ===
            "getGroupMessages"
          ) {
            if (!socket.username) {
              return;
            }

            await pool.query(`
              DELETE FROM messages
              WHERE is_group = TRUE
              AND created_at <
                NOW() - INTERVAL '24 hours'
            `);

            const result =
              await pool.query(
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

          /* =========================
             ALLGEMEIN NACHRICHT
          ========================= */

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
              !isAdmin(username)
            ) {
              send(socket, {
                type: "error",
                text:
                  "Du darfst im Allgemein-Chat nur lesen."
              });

              return;
            }

            const text = String(
              data.text || ""
            ).trim();

            const imageUrl =
              typeof data.imageUrl ===
              "string"
                ? data.imageUrl
                : null;

            if (
              !text &&
              !imageUrl
            ) {
              return;
            }

            const result =
              await pool.query(
                `
                INSERT INTO messages
                (
                  sender,
                  text,
                  image_url,
                  is_group
                )
                VALUES
                ($1, $2, $3, TRUE)
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

            const row =
              result.rows[0];

            const message = {
              username:
                row.sender,

              text:
                row.text,

              imageUrl:
                row.imageUrl,

              time:
                Number(row.time),

              isAdmin:
                isAdmin(username)
            };

            broadcastGroup({
              type:
                "groupMessage",
              message
            });

            return;
          }

          /* =========================
             PRIVATE NACHRICHT
          ========================= */

          if (
            data.type ===
            "message"
          ) {
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
              typeof data.imageUrl ===
              "string"
                ? data.imageUrl
                : null;

            if (
              !from ||
              !to ||
              (!text && !imageUrl)
            ) {
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
                  image_url,
                  is_group
                )
                VALUES
                ($1, $2, $3, $4, FALSE)
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
              type:
                "message",

              from,

              to,

              text,

              imageUrl,

              time:
                Number(
                  result.rows[0]
                    .time
                ),

              senderIsAdmin:
                isAdmin(from)
            };

            /*
             * Absender bekommt die Nachricht
             * ebenfalls zurück.
             */

            send(
              socket,
              message
            );

            /*
             * Empfänger bekommt sie live.
             */

            for (
              const client of wss.clients
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

          /* =========================
             BENUTZER FÜR ADMINS
          ========================= */

          if (
            data.type ===
            "getUsers"
          ) {
            if (
              !isAdmin(
                socket.username
              )
            ) {
              send(socket, {
                type: "error",
                text:
                  "Nur Admins dürfen Benutzer sehen."
              });

              return;
            }

            const result =
              await pool.query(
                `
                SELECT
                  username,
                  created_at
                FROM users
                ORDER BY created_at ASC
                `
              );

            send(socket, {
              type: "users",
              users:
                result.rows.map(
                  row => ({
                    username:
                      row.username,
                    createdAt:
                      row.created_at
                  })
                )
            });

            return;
          }

          /* =========================
             BILDER
          ========================= */

          /*
           * Die aktuelle index.html sendet Bilder
           * als Base64 mit "uploadImage".
           *
           * Wir speichern sie direkt als Data-URL
           * und antworten mit imageUploaded.
           */

          if (
            data.type ===
            "uploadImage"
          ) {
            if (!socket.username) {
              return;
            }

            const image =
              String(
                data.image || ""
              );

            if (
              !image.startsWith(
                "data:image/"
              )
            ) {
              send(socket, {
                type: "error",
                text:
                  "Ungültiges Bild."
              });

              return;
            }

            /*
             * Maximal ungefähr 8 MB.
             */

            if (
              image.length >
              11 * 1024 * 1024
            ) {
              send(socket, {
                type: "error",
                text:
                  "Das Bild ist zu groß."
              });

              return;
            }

            /*
             * Kein echter Upload nötig:
             * Die index.html bekommt die Data-URL
             * direkt zurück.
             */

            send(socket, {
              type:
                "imageUploaded",
              url:
                image
            });

            return;
          }

        } catch (error) {
          console.error(
            "❌ Serverfehler:",
            error
          );

          send(socket, {
            type:
              "error",
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
        if (socket.username) {
          console.log(
            `📱 ${socket.username} getrennt`
          );
        }
      }
    );
  }
);

/* =========================
   AUFRÄUMEN
========================= */

setInterval(
  async () => {
    try {
      await pool.query(`
        DELETE FROM messages
        WHERE is_group = TRUE
        AND created_at <
          NOW() - INTERVAL '24 hours'
      `);

      await pool.query(`
        DELETE FROM password_resets
        WHERE expires_at < NOW()
        OR used = TRUE
      `);
    } catch (error) {
      console.error(
        "❌ Bereinigung:",
        error.message
      );
    }
  },
  10 * 60 * 1000
);

/* =========================
   START
========================= */

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
```
