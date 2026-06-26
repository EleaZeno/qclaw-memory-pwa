// Minimal service worker: app-shell cache only. NEVER cache memory data or tokens.
const SHELL = 'qclaw-shell-v1';
const ASSETS = ['./index.html','./app.js','./manifest.webmanifest','./icon-180.png','./icon-512.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(SHELL).then(c => c.addAll(ASSETS)).catch(()=>{})); self.skipWaiting(); });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k=>k!==SHELL).map(k=>caches.delete(k))))); self.clients.claim(); });
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // never touch GitHub API responses (memory ciphertext / keyring) — always network
  if (url.hostname === 'api.github.com') return;
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
});
