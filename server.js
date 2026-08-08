const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const WebSocket = require("ws");
const webpush = require("web-push");
const { Pool } = require("pg");

const PORT = process.env.PORT || 3000;
const ACCESS_CODE = process.env.ACCESS_CODE || "";

const APP_URL =
  process.env.APP_URL ||
  "https://fortx.onrender.com";

const VAPID_PUBLIC_KEY =
  process.env.VAPID_PUBLIC_KEY || "";

const VAPID_PRIVATE_KEY =
  process.env.VAPID_PRIVATE_KEY || "";

const VAPID_EMAIL =
  process.env.VAPID_EMAIL ||
  "mailto:admin@example.com";

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

const server = http.createServer();
const wss = new WebSocket.Server({ server });

if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(
    VAPID_EMAIL,
    VAPID_PUBLIC_KEY,
    VAPID_PRIVATE_KEY
  );
}

function send(socket, data) {
  if (
    socket &&
    socket.readyState === WebSocket.OPEN
  ) {
    socket.send(JSON.stringify(data));
  }
}

function normalizeUsername(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function hashPassword(password) {
  const salt = crypto
    .randomBytes(16)
    .toString("hex");

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
    const originalHash = Buffer.from(
      parts[1],
      "hex"
    );

    const hash = crypto.scryptSync(
      password,
      salt,
      64
    );

    return crypto.timingSafeEqual(
      hash,
      originalHash
    );
  } catch {
    return false;
  }
}

function createToken() {
  return crypto
    .randomBytes(32)
    .toString("hex");
}

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function isAdmin(username) {
  return GROUP_ADMINS.includes(
    normalizeUsername(username)
  );
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
      friend TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(username, friend)
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
    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      endpoint TEXT NOT NULL UNIQUE,
      subscription JSONB NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  console.log("🗄️ Datenbank bereit");
}

async function cleanOldData() {
  await pool.query(`
    DELETE FROM messages
    WHERE is_group = TRUE
    AND created_at < NOW() - INTERVAL '24 hours'
  `);

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

async function sendPushToUser(
  username,
  title,
  body,
  url = "/"
) {
  if (
    !VAPID_PUBLIC_KEY ||
    !VAPID_PRIVATE_KEY
  ) {
    return;
  }

  const result = await pool.query(
    `
    SELECT endpoint, subscription
    FROM push_subscriptions
    WHERE username = $1
    `,
    [username]
  );

  const payload = JSON.stringify({
    title,
    body,
    url
  });

  for (const row of result.rows) {
    try {
      await webpush.sendNotification(
        row.subscription,
        payload
      );
    } catch (error) {
      if (
        error.statusCode === 404 ||
        error.statusCode === 410
      ) {
        await pool.query(
          `
          DELETE FROM push_subscriptions
          WHERE endpoint = $1
          `,
          [row.endpoint]
        );
      } else {
        console.log(
          "❌ Push-Fehler:",
          error.message
        );
      }
    }
  }
}

function getIndexHtml() {
  return fs.readFileSync(
    path.join(__dirname, "index.html"),
    "utf8"
  );
}

function sendIndex(res) {
  try {
    const html = getIndexHtml();

    res.writeHead(200, {
      "Content-Type":
        "text/html; charset=utf-8",
      "Cache-Control":
        "no-cache, no-store, must-revalidate"
    });

    res.end(html);
  } catch (error) {
    console.error(error);

    res.writeHead(500, {
      "Content-Type":
        "text/plain; charset=utf-8"
    });

    res.end(
      "index.html konnte nicht geladen werden."
    );
  }
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    "Content-Type":
      "application/json; charset=utf-8"
  });

  res.end(JSON.stringify(data));
}

const serviceWorker = `
self.addEventListener("install", event => {
  self.skipWaiting();
});

self.addEventListener("activate", event => {
  event.waitUntil(
    self.clients.claim()
  );
});

self.addEventListener("fetch", event => {
  if (event.request.method !== "GET") {
    return;
  }

  event.respondWith(
    fetch(event.request).catch(() =>
      caches.match(event.request)
    )
  );
});

self.addEventListener("push", event => {
  let data = {};

  try {
    data = event.data
      ? event.data.json()
      : {};
  } catch {}

  const title =
    data.title ||
    "Privater Messenger";

  const options = {
    body:
      data.body ||
      "Neue Nachricht",
    icon: "/icon.svg",
    badge: "/icon.svg",
    data: {
      url:
        data.url ||
        "/"
    },
    vibrate: [
      200,
      100,
      200
    ]
  };

  event.waitUntil(
    self.registration.showNotification(
      title,
      options
    )
  );
});

self.addEventListener(
  "notificationclick",
  event => {
    event.notification.close();

    const url =
      event.notification.data &&
      event.notification.data.url
        ? event.notification.data.url
        : "/";

    event.waitUntil(
      clients.matchAll({
        type: "window",
        includeUncontrolled: true
      }).then(list => {
        for (const client of list) {
          if ("focus" in client) {
            client.navigate(url);
            return client.focus();
          }
        }

        if (clients.openWindow) {
          return clients.openWindow(url);
        }
      })
    );
  }
);
`;

const manifest = {
  name: "Privater Messenger",
  short_name: "Messenger",
  start_url: "/",
  display: "standalone",
  background_color: "#000000",
  theme_color: "#000000",
  description:
    "Privater Messenger",
  icons: [
    {
      src: "/icon.svg",
      sizes: "any",
      type: "image/svg+xml",
      purpose: "any maskable"
    }
  ]
};

const iconSvg = `
<svg xmlns="http://www.w3.org/2000/svg"
width="512" height="512"
viewBox="0 0 512 512">
<rect width="512" height="512"
rx="110" fill="#000"/>
<circle cx="256" cy="220"
r="130" fill="#fff"/>
<path d="M150 350 L135 405 L205 365"
fill="#fff"/>
<circle cx="205" cy="220"
r="22" fill="#000"/>
<circle cx="256" cy="220"
r="22" fill="#000"/>
<circle cx="307" cy="220"
r="22" fill="#000"/>
</svg>
`;

server.on("request", async (req, res) => {
  try {
    const url =
      new URL(
        req.url,
        `http://${req.headers.host}`
      );

    if (
      url.pathname === "/health"
    ) {
      sendJson(res, 200, {
        status: "ok"
      });
      return;
    }

    if (
      url.pathname === "/manifest.json"
    ) {
      sendJson(
        res,
        200,
        manifest
      );
      return;
    }

    if (
      url.pathname === "/sw.js"
    ) {
      res.writeHead(200, {
        "Content-Type":
          "application/javascript",
        "Cache-Control":
          "no-cache"
      });

      res.end(serviceWorker);
      return;
    }

    if (
      url.pathname === "/icon.svg"
    ) {
      res.writeHead(200, {
        "Content-Type":
          "image/svg+xml",
        "Cache-Control":
          "public, max-age=86400"
      });

      res.end(iconSvg);
      return;
    }

    if (
      url.pathname === "/api/vapid-public-key"
    ) {
      sendJson(res, 200, {
        publicKey:
          VAPID_PUBLIC_KEY || null
      });
      return;
    }

    if (
      url.pathname === "/"
    ) {
      sendIndex(res);
      return;
    }

    sendIndex(res);
  } catch (error) {
    console.error(error);

    res.writeHead(500);
    res.end("Serverfehler");
  }
});

wss.on("connection", socket => {
  console.log(
    "📱 Gerät verbunden"
  );

  socket.on("message", async raw => {
    try {
      const data =
        JSON.parse(
          raw.toString()
        );

      /*
       * REGISTRIEREN
       */

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
              "Server-Zugangscode ist nicht eingerichtet."
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
          username.length < 3 ||
          username.length > 30
        ) {
          send(socket, {
            type: "error",
            text:
              "Benutzername muss 3 bis 30 Zeichen lang sein."
          });
          return;
        }

        if (
          !/^[a-z0-9_.-]+$/.test(
            username
          )
        ) {
          send(socket, {
            type: "error",
            text:
              "Benutzername darf nur Buchstaben, Zahlen, Punkt, Bindestrich und Unterstrich enthalten."
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

        const existing =
          await pool.query(
            `
            SELECT username
            FROM users
            WHERE username = $1
            `,
            [username]
          );

        if (
          existing.rows.length
        ) {
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

        socket.username =
          username;

        send(socket, {
          type:
            "registered",
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
          normalizeUsername(
            data.username
          );

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
          !result.rows.length ||
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
          type:
            "loggedIn",
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
        if (!socket.username) {
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

        const exists =
          await pool.query(
            `
            SELECT username
            FROM users
            WHERE username = $1
            `,
            [friend]
          );

        if (!exists.rows.length) {
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
          (username, friend)
          VALUES ($1, $2)
          ON CONFLICT DO NOTHING
          `,
          [
            socket.username,
            friend
          ]
        );

        await pool.query(
          `
          INSERT INTO friends
          (username, friend)
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

        for (
          const client of wss.clients
        ) {
          if (
            client.readyState ===
              WebSocket.OPEN &&
            client.username ===
              friend
          ) {
            send(client, {
              type:
                "friendAdded",
              username:
                socket.username
            });
          }
        }

        return;
      }

      /*
       * FREUNDE LADEN
       */

      if (
        data.type ===
        "getFriends"
      ) {
        if (!socket.username) {
          return;
        }

        const result =
          await pool.query(
            `
            SELECT friend
            FROM friends
            WHERE username = $1
            ORDER BY friend ASC
            `,
            [socket.username]
          );

        send(socket, {
          type:
            "friends",
          friends:
            result.rows.map(
              row =>
                row.friend
            )
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

        if (!target.rows.length) {
          send(socket, {
            type: "error",
            text:
              "Benutzer nicht gefunden."
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

        const message = {
          from,
          to,
          text,
          time:
            Date.now()
        };

        send(socket, {
          type:
            "message",
          ...message
        });

        let online =
          false;

        for (
          const client of wss.clients
        ) {
          if (
            client.readyState ===
              WebSocket.OPEN &&
            client.username ===
              to
          ) {
            online = true;

            send(client, {
              type:
                "message",
              ...message
            });
          }
        }

        if (!online) {
          await sendPushToUser(
            to,
            `Neue Nachricht von @${from}`,
            text,
            "/"
          );
        }

        return;
      }

      /*
       * PRIVATE CHAT LADEN
       */

      if (
        data.type ===
        "getPrivateMessages"
      ) {
        if (!socket.username) {
          return;
        }

        const friend =
          normalizeUsername(
            data.friend
          );

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
              socket.username,
              friend
            ]
          );

        send(socket, {
          type:
            "privateMessages",
          friend,
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
                  Number(
                    row.time
                  )
              })
            )
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

        await cleanOldData();

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
                  Number(
                    row.time
                  )
              })
            )
        });

        return;
      }

      /*
       * GRUPPENCHAT SENDEN
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
          !isAdmin(username)
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
       * PASSWORT VERGESSEN
       */

      if (
        data.type ===
        "forgotPassword"
      ) {
        const username =
          normalizeUsername(
            data.username
          );

        const user =
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

        if (!user.rows.length) {
          return;
        }

        const requestId =
          createToken();

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
              requestId,
              username,
              time:
                Date.now()
            });
          }
        }

        return;
      }

      /*
       * RESET-LINK ERSTELLEN
       */

      if (
        data.type ===
        "createPasswordReset"
      ) {
        if (
          !socket.username ||
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
          await pool.query(
            `
            SELECT username
            FROM users
            WHERE username = $1
            `,
            [username]
          );

        if (!user.rows.length) {
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
          createToken();

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

        const resetUrl =
          `${APP_URL}/?reset=${encodeURIComponent(
            token
          )}`;

        send(socket, {
          type:
            "passwordResetLink",
          username,
          resetUrl
        });

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
          String(
            data.token || ""
          );

        const password =
          String(
            data.password || ""
          );

        if (
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

        if (!result.rows.length) {
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
       * PUSH REGISTRIEREN
       */

      if (
        data.type ===
        "subscribePush"
      ) {
        if (!socket.username) {
          return;
        }

        const subscription =
          data.subscription;

        if (
          !subscription ||
          !subscription.endpoint
        ) {
          return;
        }

        await pool.query(
          `
          INSERT INTO push_subscriptions
          (
            username,
            endpoint,
            subscription
          )
          VALUES ($1, $2, $3)
          ON CONFLICT(endpoint)
          DO UPDATE SET
            username = EXCLUDED.username,
            subscription = EXCLUDED.subscription
          `,
          [
            socket.username,
            subscription.endpoint,
            JSON.stringify(
              subscription
            )
          ]
        );

        send(socket, {
          type:
            "pushSubscribed"
        });

        return;
      }

      /*
       * PUSH ABBESTELLEN
       */

      if (
        data.type ===
        "unsubscribePush"
      ) {
        if (!socket.username) {
          return;
        }

        const endpoint =
          String(
            data.endpoint || ""
          );

        if (endpoint) {
          await pool.query(
            `
            DELETE FROM push_subscriptions
            WHERE endpoint = $1
              AND username = $2
            `,
            [
              endpoint,
              socket.username
            ]
          );
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
  cleanOldData().catch(
    error =>
      console.log(
        "❌ Aufräumfehler:",
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
