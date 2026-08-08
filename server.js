const http = require("http");
const WebSocket = require("ws");

const PORT = process.env.PORT || 3000;

const users = new Map();
const friends = new Map();

const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");

  if (req.url === "/health") {
    res.writeHead(200, {
      "Content-Type": "application/json"
    });

    res.end(JSON.stringify({ status: "ok" }));
    return;
  }

  res.writeHead(200, {
    "Content-Type": "text/plain; charset=utf-8"
  });

  res.end("Privater Messenger Server läuft! 🔐");
});

const wss = new WebSocket.Server({ server });

function send(socket, data) {
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(data));
  }
}

wss.on("connection", (socket) => {

  console.log("📱 Gerät verbunden");

  socket.on("message", (raw) => {

    try {

      const data = JSON.parse(raw.toString());

      if (data.type === "register") {

        const username =
          String(data.username || "")
            .trim()
            .toLowerCase();

        if (!username) {
          send(socket, {
            type: "error",
            text: "Benutzername fehlt."
          });
          return;
        }

        users.set(username, socket);

        if (!friends.has(username)) {
          friends.set(username, new Set());
        }

        socket.username = username;

        send(socket, {
          type: "registered",
          username
        });

        console.log(
          `👤 Benutzer verbunden: ${username}`
        );

        return;
      }

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

        if (from === to) {
          send(socket, {
            type: "error",
            text: "Du kannst dich nicht selbst hinzufügen."
          });
          return;
        }

        const target =
          users.get(to);

        if (!target) {
          send(socket, {
            type: "error",
            text: "Dieser Benutzer ist gerade nicht online."
          });
          return;
        }

        send(target, {
          type: "friendRequest",
          from
        });

        send(socket, {
          type: "requestSent",
          to
        });

        return;
      }

      if (data.type === "acceptFriend") {

        const username =
          socket.username;

        const friend =
          String(data.username || "")
            .trim()
            .toLowerCase();

        if (!username || !friend) {
          return;
        }

        if (!friends.has(username)) {
          friends.set(
            username,
            new Set()
          );
        }

        if (!friends.has(friend)) {
          friends.set(
            friend,
            new Set()
          );
        }

        friends
          .get(username)
          .add(friend);

        friends
          .get(friend)
          .add(username);

        send(socket, {
          type: "friendAdded",
          username: friend
        });

        const friendSocket =
          users.get(friend);

        if (friendSocket) {

          send(friendSocket, {
            type: "friendAdded",
            username
          });

        }

        return;
      }

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

        const target =
          users.get(to);

        if (target) {

          send(target, {
            type: "message",
            from,
            to,
            text
          });

        }

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

    }

  });

  socket.on("close", () => {

    if (socket.username) {

      users.delete(
        socket.username
      );

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
