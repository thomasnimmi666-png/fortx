const http = require("http");
const WebSocket = require("ws");

const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  if (req.url === "/health") {
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
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

wss.on("connection", (socket) => {
  console.log("Neues Gerät verbunden");

  socket.send(JSON.stringify({
    type: "system",
    text: "🟢 Mit dem Messenger-Server verbunden"
  }));

  socket.on("message", (data) => {
    for (const client of wss.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(data.toString());
      }
    }
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server läuft auf Port ${PORT}`);
});
