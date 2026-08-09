```js
const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const WebSocket = require("ws");
const { Pool } = require("pg");

const PORT = Number(process.env.PORT || 3000);
const ACCESS_CODE = String(process.env.ACCESS_CODE || "");
const APP_URL = String(process.env.APP_URL || "");

const GROUP_ADMINS = [
  "saftpresse040",
  "thcliquide"
];

function normalizeUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function isAdmin(username) {
  return GROUP_ADMINS.includes(
    normalizeUsername(username)
  );
}

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
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto.scryptSync(
    password,
    salt,
    64
  ).toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const parts = String(stored || "").split(":");

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

/* =========================
   DATENBANK
========================= */

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
   * Fehlende Spalten bei älteren Datenbanken
   * automatisch ergänzen.
   */

  await pool.query(`
    ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS image_url TEXT
  `);

  await pool.query(`
    ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS receiver TEXT
  `);

  await pool.query(`
    ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS text TEXT
  `);

  await pool.query(`
    ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS is_group BOOLEAN DEFAULT FALSE
  `);

  /*
   * Alte friends-Tabelle reparieren.
   *
   * Falls friend_username fehlt, wird die Spalte
   * automatisch angelegt.
   */

  await pool.query(`
    ALTER TABLE friends
    ADD COLUMN IF NOT EXISTS friend_username TEXT
  `);

  console.log("🗄️ Datenbank bereit");
}

/* =========================
   ADMIN-KONTAKTE
========================= */

async function ensureAdminContacts(username) {
  const normalized = normalizeUsername(username);

  for (const admin of GROUP_ADMINS) {
    if (admin === normalized) {
      continue;
    }

    await pool.query(`
      INSERT INTO friends
      (
        username,
        friend_username
      )
      VALUES ($1, $2)
      ON CONFLICT DO NOTHING
    `, [
      normalized,
      admin
    ]);

    await pool.query(`
      INSERT INTO friends
      (
        username,
        friend_username
      )
      VALUES ($1, $2)
      ON CONFLICT DO NOTHING
    `, [
      admin,
      normalized
    ]);
  }
}

/* =========================
   AUFRÄUMEN
========================= */

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

/* =========================
   BROADCAST
========================= */

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

  const file = path.normalize(
    path.join(__dirname, requested)
  );

  const root = path.normalize(__dirname);

  if (
    file !== root &&
    !file.startsWith(root + path.sep)
  ) {
    return null;
  }

  return file;
}

/* =========================
   HTTP SERVER
========================= */

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

    const ext = path
      .extname(file)
      .toLowerCase();

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

/* =========================
   WEBSOCKET
========================= */

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

          /* =========================
             REGISTRIERUNG
          ========================= */

          if (
            data.type ===
            "register"
          ) {
            const username =
              normalizeUsername(
                data.username
              );

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
                  "ACCESS_CODE fehlt auf dem Server."
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
              !/^[a-z0-9_]{3,30}$/.test(
                username
              )
            ) {
              send(socket, {
                type: "error",
                text:
                  "Benutzername: 3–30 Zeichen, nur a-z, 0-9 und _."
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
              await pool.query(`
                SELECT 1
                FROM users
                WHERE username = $1
              `, [
                username
              ]);

            if (
              exists.rowCount
            ) {
              send(socket, {
                type: "error",
                text:
                  "Benutzername bereits vergeben."
              });

              return;
            }

            await pool.query(`
              INSERT INTO users
              (
                username,
                password_hash
              )
              VALUES ($1, $2)
            `, [
              username,
              hashPassword(
                password
              )
            ]);

            await ensureAdminContacts(
              username
            );

            socket.username =
              username;

            send(socket, {
              type:
                "registered",
              username,
              isAdmin:
                isAdmin(
                  username
                )
            });

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
                send(client, {
                  type:
                    "newUser",
                  username
                });
              }
            }

            return;
          }

          /* =========================
             LOGIN
          ========================= */

          if (
            data.type ===
            "login"
          ) {
            const username =
              normalizeUsername(
                data.username
              );

            const password =
              String(
                data.password || ""
              );

            const result =
              await pool.query(`
                SELECT
                  username,
                  password_hash
                FROM users
                WHERE username = $1
              `, [
                username
              ]);

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

            await ensureAdminContacts(
              username
            );

            socket.username =
              username;

            send(socket, {
              type:
                "loggedIn",
              username,
              isAdmin:
                isAdmin(
                  username
                )
            });

            return;
          }

          /* =========================
             PASSWORT VERGESSEN
          ========================= */

          if (
            data.type ===
            "forgotPassword"
          ) {
            const username =
              normalizeUsername(
                data.username
              );

            if (!username) {
              send(socket, {
                type: "error",
                text:
                  "Bitte Benutzername eingeben."
              });

              return;
            }

            const result =
              await pool.query(`
                SELECT username
                FROM users
                WHERE username = $1
              `, [
                username
              ]);

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
                  request
                );
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

            const username =
              normalizeUsername(
                data.username
              );

            const user =
              await pool.query(`
                SELECT username
                FROM users
                WHERE username = $1
              `, [
                username
              ]);

            if (
              !user.rowCount
            ) {
              send(socket, {
                type: "error",
                text:
                  "Benutzer nicht gefunden."
              });

              return;
            }

            await pool.query(`
              DELETE FROM password_resets
              WHERE username = $1
            `, [
              username
            ]);

            const token =
              crypto
                .randomBytes(32)
                .toString("hex");

            await pool.query(`
              INSERT INTO password_resets
              (
                token_hash,
                username,
                expires_at
              )
              VALUES
              (
                $1,
                $2,
                NOW() + INTERVAL '15 minutes'
              )
            `, [
              hashToken(token),
              username
            ]);

            const baseUrl =
              APP_URL ||
              (
                process.env
                  .RENDER_EXTERNAL_HOSTNAME
                  ? `https://${process.env.RENDER_EXTERNAL_HOSTNAME}`
                  : `http://localhost:${PORT}`
              );

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
             PASSWORT RESET
          ========================= */

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
              await pool.query(`
                SELECT username
                FROM password_resets
                WHERE token_hash = $1
                AND used = FALSE
                AND expires_at > NOW()
              `, [
                hashToken(token)
              ]);

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

            await pool.query(`
              UPDATE users
              SET password_hash = $1
              WHERE username = $2
            `, [
              hashPassword(
                password
              ),
              username
            ]);

            await pool.query(`
              UPDATE password_resets
              SET used = TRUE
              WHERE token_hash = $1
            `, [
              hashToken(token)
            ]);

            send(socket, {
              type:
                "passwordResetSuccess",
              username
            });

            return;
          }

          /* =========================
             BENUTZERLISTE
          ========================= */

          if (
            data.type ===
            "getUsers"
          ) {
            if (
              !socket.username
            ) {
              return;
            }

            if (
              !isAdmin(
                socket.username
              )
            ) {
              send(socket, {
                type: "error",
                text:
                  "Nur Admins dürfen die Benutzerliste sehen."
              });

              return;
            }

            const result =
              await pool.query(`
                SELECT
                  username,
                  created_at
                FROM users
                ORDER BY username ASC
              `);

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
             FREUND HINZUFÜGEN
          ========================= */

          if (
            data.type ===
            "addFriend"
          ) {
            if (
              !socket.username
            ) {
              return;
            }

            const friend =
              normalizeUsername(
                data.username
              );

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
              await pool.query(`
                SELECT 1
                FROM users
                WHERE username = $1
              `, [
                friend
              ]);

            if (
              !user.rowCount
            ) {
              send(socket, {
                type: "error",
                text:
                  "Benutzer nicht gefunden."
              });

              return;
            }

            await pool.query(`
              INSERT INTO friends
              (
                username,
                friend_username
              )
              VALUES ($1, $2)
              ON CONFLICT DO NOTHING
            `, [
              socket.username,
              friend
            ]);

            send(socket, {
              type:
                "friendAdded",
              username:
                friend
            });

            return;
          }

          /* =========================
             FREUNDE LADEN
          ========================= */

          if (
            data.type ===
            "getFriends"
          ) {
            if (
              !socket.username
            ) {
              return;
            }

            await ensureAdminContacts(
              socket.username
            );

            const result =
              await pool.query(`
                SELECT
                  friend_username AS username
                FROM friends
                WHERE username = $1
                ORDER BY friend_username
              `, [
                socket.username
              ]);

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
             PRIVATE NACHRICHTEN
          ========================= */

          if (
            data.type ===
            "getPrivateMessages"
          ) {
            if (
              !socket.username
            ) {
              return;
            }

            const other =
              normalizeUsername(
                data.username
              );

            const result =
              await pool.query(`
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
              `, [
                socket.username,
                other
              ]);

            send(socket, {
              type:
                "privateMessages",
              username:
                other,
              messages:
                result.rows.map(
                  row => ({
                    from:
                      row.from,
                    to:
                      row.to,
                    text:
                      row.text ||
                      "",
                    imageUrl:
                      row.imageUrl ||
                      null,
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
             GRUPPENCHAT LADEN
          ========================= */

          if (
            data.type ===
            "getGroupMessages"
          ) {
            if (
              !socket.username
            ) {
              return;
            }

            await cleanOldGroupMessages();

            const result =
              await pool.query(`
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
              `);

            send(socket, {
              type:
                "groupMessages",
              messages:
                result.rows.map(
                  row => ({
                    username:
                      row.username,
                    text:
                      row.text ||
                      "",
                    imageUrl:
                      row.imageUrl ||
                      null,
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
             GRUPPENNACHRICHT
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

            const text =
              String(
                data.text || ""
              ).trim();

            const imageUrl =
              data.imageUrl
                ? String(
                    data.imageUrl
                  )
                : null;

            if (
              !text &&
              !imageUrl
            ) {
              return;
            }

            const result =
              await pool.query(`
                INSERT INTO messages
                (
                  sender,
                  text,
                  image_url,
                  is_group
                )
                VALUES
                (
                  $1,
                  $2,
                  $3,
                  TRUE
                )
                RETURNING
                  sender,
                  text,
                  image_url AS "imageUrl",
                  EXTRACT(
                    EPOCH FROM created_at
                  ) * 1000 AS time
              `, [
                username,
                text || null,
                imageUrl
              ]);

            const row =
              result.rows[0];

            await broadcastGroup({
              type:
                "groupMessage",
              message: {
                username:
                  row.sender,
                text:
                  row.text || "",
                imageUrl:
                  row.imageUrl ||
                  null,
                time:
                  Number(
                    row.time
                  ),
                isAdmin:
                  true
              }
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

            const to =
              normalizeUsername(
                data.to
              );

            const text =
              String(
                data.text || ""
              ).trim();

            const imageUrl =
              data.imageUrl
                ? String(
                    data.imageUrl
                  )
                : null;

            if (
              !from ||
              !to ||
              (!text &&
                !imageUrl)
            ) {
              return;
            }

            const target =
              await pool.query(`
                SELECT 1
                FROM users
                WHERE username = $1
              `, [
                to
              ]);

            if (
              !target.rowCount
            ) {
              send(socket, {
                type: "error",
                text:
                  "Benutzer nicht gefunden."
              });

              return;
            }

            const result =
              await pool.query(`
                INSERT INTO messages
                (
                  sender,
                  receiver,
                  text,
                  image_url,
                  is_group
                )
                VALUES
                (
                  $1,
                  $2,
                  $3,
                  $4,
                  FALSE
                )
                RETURNING
                  EXTRACT(
                    EPOCH FROM created_at
                  ) * 1000 AS time
              `, [
                from,
                to,
                text || null,
                imageUrl
              ]);

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

            send(
              socket,
              message
            );

            for (
              const client
              of wss.clients
            ) {
              if (
                client.readyState ===
                  WebSocket.OPEN &&
                client.username ===
                  to
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
             BILD UPLOAD
          ========================= */

          if (
            data.type ===
            "uploadImage"
          ) {
            if (
              !socket.username
            ) {
              return;
            }

            const image =
              String(
                data.image || ""
              );

            const target =
              normalizeUsername(
                data.to
              );

            const general =
              data.target ===
              "general";

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

            if (
              general &&
              !isAdmin(
                socket.username
              )
            ) {
              send(socket, {
                type: "error",
                text:
                  "Nur Admins können Bilder im Allgemein-Chat senden."
              });

              return;
            }

            if (
              !general &&
              !target
            ) {
              send(socket, {
                type: "error",
                text:
                  "Kein Empfänger ausgewählt."
              });

              return;
            }

            if (
              image.length >
              12 * 1024 * 1024
            ) {
              send(socket, {
                type: "error",
                text:
                  "Das Bild ist zu groß."
              });

              return;
            }

            const match =
              image.match(
                /^data:image\/([a-zA-Z0-9+.-]+);base64,(.+)$/
              );

            if (!match) {
              send(socket, {
                type: "error",
                text:
                  "Bildformat wird nicht unterstützt."
              });

              return;
            }

            let extension =
              match[1].toLowerCase();

            if (
              extension ===
              "jpeg"
            ) {
              extension = "jpg";
            }

            const allowed = [
              "png",
              "jpg",
              "gif",
              "webp"
            ];

            if (
              !allowed.includes(
                extension
              )
            ) {
              send(socket, {
                type: "error",
                text:
                  "Erlaubt sind PNG, JPG, GIF und WEBP."
              });

              return;
            }

            const uploadDir =
              path.join(
                __dirname,
                "uploads"
              );

            await fs.promises.mkdir(
              uploadDir,
              {
                recursive:
                  true
              }
            );

            const filename =
              `${Date.now()}-${crypto.randomBytes(8).toString("hex")}.${extension}`;

            const fullPath =
              path.join(
                uploadDir,
                filename
              );

            await fs.promises.writeFile(
              fullPath,
              Buffer.from(
                match[2],
                "base64"
              )
            );

            const baseUrl =
              APP_URL ||
              (
                process.env
                  .RENDER_EXTERNAL_HOSTNAME
                  ? `https://${process.env.RENDER_EXTERNAL_HOSTNAME}`
                  : `http://localhost:${PORT}`
              );

            const imageUrl =
              `${baseUrl}/uploads/${filename}`;

            if (general) {
              const result =
                await pool.query(`
                  INSERT INTO messages
                  (
                    sender,
                    text,
                    image_url,
                    is_group
                  )
                  VALUES
                  (
                    $1,
                    NULL,
                    $2,
                    TRUE
                  )
                  RETURNING
                    sender,
                    image_url AS "imageUrl",
                    EXTRACT(
                      EPOCH FROM created_at
                    ) * 1000 AS time
                `, [
                  socket.username,
                  imageUrl
                ]);

              const row =
                result.rows[0];

              await broadcastGroup({
                type:
                  "groupMessage",
                message: {
                  username:
                    row.sender,
                  text: "",
                  imageUrl:
                    row.imageUrl,
                  time:
                    Number(
                      row.time
                    ),
                  isAdmin:
                    true
                }
              });

              return;
            }

            const targetUser =
              await pool.query(`
                SELECT 1
                FROM users
                WHERE username = $1
              `, [
                target
              ]);

            if (
              !targetUser.rowCount
            ) {
              send(socket, {
                type: "error",
                text:
                  "Benutzer nicht gefunden."
              });

              return;
            }

            const result =
              await pool.query(`
                INSERT INTO messages
                (
                  sender,
                  receiver,
                  text,
                  image_url,
                  is_group
                )
                VALUES
                (
                  $1,
                  $2,
                  NULL,
                  $3,
                  FALSE
                )
                RETURNING
                  EXTRACT(
                    EPOCH FROM created_at
                  ) * 1000 AS time
              `, [
                socket.username,
                target,
                imageUrl
              ]);

            const message = {
              type:
                "message",
              from:
                socket.username,
              to:
                target,
              text: "",
              imageUrl,
              time:
                Number(
                  result.rows[0]
                    .time
                ),
              senderIsAdmin:
                isAdmin(
                  socket.username
                )
            };

            send(
              socket,
              message
            );

            for (
              const client
              of wss.clients
            ) {
              if (
                client.readyState ===
                  WebSocket.OPEN &&
                client.username ===
                  target
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

/* =========================
   AUTOMATISCHE BEREINIGUNG
========================= */

setInterval(
  () => {
    cleanOldGroupMessages()
      .catch(
        error =>
          console.error(
            "Gruppenchat-Bereinigung:",
            error.message
          )
      );

    cleanResetTokens()
      .catch(
        error =>
          console.error(
            "Reset-Bereinigung:",
            error.message
          )
      );
  },
  10 * 60 * 1000
);

/* =========================
   SERVER START
========================= */

initDatabase()
  .then(
    () => {
      server.listen(
        PORT,
        "0.0.0.0",
        () => {
          console.log(
            `🚀 FORTX Server läuft auf Port ${PORT}`
          );

          console.log(
            "👑 Admins:",
            GROUP_ADMINS.join(
              ", "
            )
          );
        }
      );
    }
  )
  .catch(
    error => {
      console.error(
        "❌ Datenbankfehler:",
        error
      );

      process.exit(1);
    }
  );
```
