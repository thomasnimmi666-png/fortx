const http = require("http");

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};

const server = http.createServer((req, res) => {
res.writeHead(200, {
"Content-Type": "text/plain; charset=utf-8"
});

if (req.url === "/health") {
  res.writeHead(200, {
    ...corsHeaders,
    "Content-Type": "application/json"
  });

  res.end(JSON.stringify({ status: "ok" }));
  return;
}
  res.end("Privater Messenger Server läuft! 🔐");
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
console.log(`Server läuft auf Port ${PORT}`);
});
