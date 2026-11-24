// Service worker del sito protetto.
// Serve le pagine decifrate salvate sul dispositivo dopo la password.
// Quando apri una pagina controlla (al massimo una volta al minuto) se è uscita una
// versione nuova: se sì la scarica e la decifra con la chiave salvata, e la vedrai
// alla pagina successiva. Se la password è cambiata, cancella tutto e la richiede.

importScripts('apri.js');

const DALLA_RETE = new Set(['sito.bin', 'versione.json', 'sw.js', 'apri.js']);
const INTERVALLO_CONTROLLI = 60 * 1000;

let stato = null;
let ultimoControllo = 0;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));
self.addEventListener('message', (event) => {
  if (event.data === 'rileggi') stato = null;
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const base = self.registration.scope;
  if (req.method !== 'GET' || !req.url.startsWith(base)) return;
  const url = new URL(req.url);
  let percorso = url.pathname.slice(new URL(base).pathname.length);
  try {
    percorso = decodeURIComponent(percorso);
  } catch { /* lascio com'è */ }
  if (DALLA_RETE.has(percorso)) return;
  event.respondWith(servi(event, req, url, percorso, base));
});

async function servi(event, req, url, percorso, base) {
  const navigazione = req.mode === 'navigate';
  if (navigazione || !stato) stato = await GP.leggi().catch(() => null);
  // Password cambiata: le pagine nuove vengono dalla rete (cioè chiedono la password).
  if (stato && !(stato.revocato && navigazione)) {
    const chiave = percorso === '' || percorso.endsWith('/') ? percorso + 'index.html' : percorso;
    const salvata = await caches.match(new URL(chiave, base).href, { cacheName: stato.cache });
    if (salvata) {
      if (navigazione) event.waitUntil(controlla(base));
      return salvata;
    }
    // "sezione" senza barra finale: come fa GitHub Pages, rimando a "sezione/".
    if (navigazione && !/\.[^/]+$/.test(percorso)
      && await caches.match(new URL(percorso + '/index.html', base).href, { cacheName: stato.cache })) {
      return Response.redirect(new URL(percorso + '/' + url.search, base).href, 302);
    }
  }
  return fetch(req);
}

async function controlla(base) {
  const ora = Date.now();
  if (ora - ultimoControllo < INTERVALLO_CONTROLLI) return;
  ultimoControllo = ora;
  try {
    await GP.aggiorna(base);
  } catch { /* offline o pubblicazione in corso: riprovo alla prossima pagina */ }
  stato = null;
}
