const http = require("http");

const server = http.createServer((req, res) => {
res.writeHead(200, {
"Content-Type": "text/plain; charset=utf-8"
});

res.end("Privater Messenger Server läuft! 🔐");
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
console.log(`Server läuft auf Port ${PORT}`);
});
