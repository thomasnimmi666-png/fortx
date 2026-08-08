const http = require("http");
const WebSocket = require("ws");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const ACCESS_CODE = process.env.ACCESS_CODE;

const users = new Map();
const friends = new Map();

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, originalHash] = stored.split(":");

  const hash = crypto.scryptSync(password, salt, 64);

  return crypto.timingSafeEqual(
    hash,
    Buffer.from(originalHash, "hex")
  );
}

function send(socket, data) {
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(data));
  }
}

const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");

  if (req.url === "/health") {
    res.writeHead(200, {
      "Content-Type": "application/json"
    });

    res.end(JSON.stringify({
      status: "ok"
    }));

    return;
  }

  res.writeHead(200, {
    "Content-Type": "text/plain; charset=utf-8"
  });

  res.end("Privater Messenger Server läuft! 🔐");
});

const wss = new WebSocket.Server({
  server
});

wss.on("connection", (socket) => {

  console.log("📱 Gerät verbunden");

  socket.on("message", (raw) => {

    try {

      const data = JSON.parse(raw.toString());

      // REGISTRIEREN
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
            text: "ACCESS_CODE ist auf dem Server noch nicht eingerichtet."
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

        if (!username || !password) {
          send(socket, {
            type: "error",
            text: "Benutzername und Passwort fehlen."
          });
          return;
        }

        if (username.length < 3) {
          send(socket, {
            type: "error",
            text: "Der Benutzername muss mindestens 3 Zeichen haben."
          });
          return;
        }

        if (password.length < 8) {
          send(socket, {
            type: "error",
            text: "Das Passwort muss mindestens 8 Zeichen haben."
          });
          return;
        }

        if (users.has(username)) {
          send(socket, {
            type: "error",
            text: "Dieser Benutzername ist bereits vergeben."
          });
          return;
        }

        users.set(username, {
          passwordHash: hashPassword(password),
          socket
        });

        friends.set(username, new Set());

        socket.username = username;

        send(socket, {
          type: "registered",
          username
        });

        console.log(
          `👤 Neuer Benutzer: ${username}`
        );

        return;
      }

      // EINLOGGEN
      if (data.type === "login") {

        const username =
          String(data.username || "")
            .trim()
            .toLowerCase();

        const password =
          String(data.password || "");

        const user =
          users.get(username);

        if (!user) {
          send(socket, {
            type: "error",
            text: "Benutzername oder Passwort falsch."
          });
          return;
        }

        if (!verifyPassword(password, user.passwordHash)) {
          send(socket, {
            type: "error",
            text: "Benutzername oder Passwort falsch."
          });
          return;
        }

        user.socket = socket;
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

      // FREUND HINZUFÜGEN
      if (data.type === "addFriend") {

        const from =
          socket.username;

        const to =
          String(data.username || "")
            .trim()
            .toLowerCase();

        if (!from || !to) {
          return;
        }

        if (!users.has(to)) {
          send(socket, {
            type: "error",
            text: "Benutzer nicht gefunden."
          });
          return;
        }

        if (from === to) {
          send(socket, {
            type: "error",
            text: "Du kannst dich nicht selbst hinzufügen."
          });
          return;
        }

        const target =
          users.get(to).socket;

        if (target) {
          send(target, {
            type: "friendRequest",
            from
          });
        }

        send(socket, {
          type: "requestSent",
          to
        });

        return;
      }

      // NACHRICHT
      if (data.type === "message") {

        const from =
          socket.username;

        const to =
          String(data.to || "")
            .trim()
            .toLowerCase();

        const text =
          String(data.text || "");

        if (!from || !to || !text) {
          return;
        }

        const targetUser =
          users.get(to);

        if (!targetUser) {
          send(socket, {
            type: "error",
            text: "Benutzer nicht gefunden."
          });
          return;
        }

        send(targetUser.socket, {
          type: "message",
          from,
          to,
          text
        });

        send(socket, {
          type: "message",
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
        text: "Serverfehler."
      });

    }

  });

  socket.on("close", () => {

    if (socket.username) {

      const user =
        users.get(socket.username);

      if (user) {
        user.socket = null;
      }

      console.log(
        `📱 ${socket.username} getrennt`
      );

    }

  });

});

server.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `🚀 Server läuft auf Port ${PORT}`
    );

  }
);
