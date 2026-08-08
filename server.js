const http = require("http");
const WebSocket = require("ws");

const PORT = process.env.PORT || 3000;

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

  socket.send(JSON.stringify({
    type: "system",
    text: "🟢 Mit dem Server verbunden"
  }));

  socket.on("message", (message) => {
    console.log("Nachricht erhalten:", message.toString());

    for (const client of wss.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message.toString());
      }
    }
  });

  socket.on("close", () => {
    console.log("📱 Gerät getrennt");
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server läuft auf Port ${PORT}`);
});
