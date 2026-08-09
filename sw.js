const CACHE = "privater-messenger-v1";

self.addEventListener("install", event => {
  self.skipWaiting();
});

self.addEventListener("activate", event => {
  self.clients.claim();
});

self.addEventListener("fetch", event => {
  // Netzwerkbetrieb – Messenger/WebSocket bleibt live.
});
