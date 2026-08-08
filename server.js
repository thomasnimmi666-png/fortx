const http = require("http");
const WebSocket = require("ws");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const ACCESS_CODE = process.env.ACCESS_CODE;

const GROUP_ADMINS = [
  "saftpresse040",
  "thcliquide"
];

const users = new Map();
const friends = new Map();
const groupMessages = [];

const MESSAGE_LIFETIME = 24 * 60 * 60 * 1000;

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

function broadcastGroup(data) {
  for (const client of wss.clients) {
    if (client.readyState === WebSocket.OPEN) {
      send(client, data);
    }
  }
}

function cleanGroupMessages() {
  const limit =
    Date.now() - MESSAGE_LIFETIME;

  while (
    groupMessages.length > 0 &&
    groupMessages[0].time < limit
  ) {
    groupMessages.shift();
  }
}

const server = http.createServer((req, res) => {

  res.setHeader(
    "Access-Control-Allow-Origin",
    "*"
  );

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

  socket.on("message", (raw) => {

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
          password.length < 8
        ) {
          send(socket, {
            type: "error",
            text:
              "Benutzername mindestens 3 Zeichen und Passwort mindestens 8 Zeichen."
          });
          return;
        }

        if (users.has(username)) {
          send(socket, {
            type: "error",
            text:
              "Benutzername ist bereits vergeben."
          });
          return;
        }

        users.set(username, {
          passwordHash:
            hashPassword(password),
          socket: socket
        });

        friends.set(
          username,
          new Set()
        );

        socket.username =
          username;

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

        const user =
          users.get(username);

        if (
          !user ||
          !verifyPassword(
            password,
            user.passwordHash
          )
        ) {
          send(socket, {
            type: "error",
            text:
              "Benutzername oder Passwort falsch."
          });
          return;
        }

        user.socket =
          socket;

        socket.username =
          username;

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
       * GRUPPENCHAT LADEN
       */

      if (
        data.type ===
        "getGroupMessages"
      ) {

        if (!socket.username) {
          return;
        }

        cleanGroupMessages();

        send(socket, {
          type:
            "groupMessages",
          messages:
            groupMessages
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

        cleanGroupMessages();

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

        if (!text) {
          return;
        }

        const message = {
          username,
          text,
          time: Date.now()
        };

        groupMessages.push(
          message
        );

        broadcastGroup({
          type:
            "groupMessage",
          message
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

        const from =
          socket.username;

        const to =
          String(data.username || "")
            .trim()
            .toLowerCase();

        if (!from || !to) {
          return;
        }

        if (from === to) {

          send(socket, {
            type: "error",
            text:
              "Du kannst dich nicht selbst hinzufügen."
          });

          return;
        }

        if (!users.has(to)) {

          send(socket, {
            type: "error",
            text:
              "Benutzer nicht gefunden."
          });

          return;
        }

        const target =
          users.get(to).socket;

        send(target, {
          type:
            "friendRequest",
          from
        });

        send(socket, {
          type:
            "requestSent",
          to
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
          String(data.to || "")
            .trim()
            .toLowerCase();

        const text =
          String(
            data.text || ""
          ).trim();

        if (!from || !to || !text) {
          return;
        }

        const target =
          users.get(to);

        if (!target) {

          send(socket, {
            type: "error",
            text:
              "Benutzer nicht gefunden."
          });

          return;
        }

        send(target.socket, {
          type:
            "message",
          from,
          to,
          text
        });

        send(socket, {
          type:
            "message",
          from,
          to,
          text
        });

        return;
      }

    } catch (error) {

      console.log(
        "❌ Fehler:",
        error.message
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

      const user =
        users.get(
          socket.username
        );

      if (user) {
        user.socket = null;
      }

      console.log(
        `📱 ${socket.username} getrennt`
      );
    }
  });
});

/*
 * Alle 10 Minuten alte
 * Gruppenchat-Nachrichten löschen.
 */

setInterval(() => {
  cleanGroupMessages();
}, 10 * 60 * 1000);

server.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `🚀 Server läuft auf Port ${PORT}`
    );

  }
);
