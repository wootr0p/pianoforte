/* Apertura del sito protetto da password.
 *
 * Lo usano la pagina della password (ingresso.html), il service worker (sw.js,
 * con importScripts) e lo strumento che cifra il sito (strumenti/cifra.mjs).
 *
 * Come funziona la cifratura:
 *  - password → PBKDF2-SHA256 (sale, N iterazioni) → 32 byte: la chiave privata d.
 *    Da d si ricava la chiave pubblica P = X25519(d, 9), salvata in protezione/chiave.json.
 *  - a ogni pubblicazione lo strumento crea una chiave usa-e-getta e, con E = X25519(e, 9),
 *    e calcola il segreto X25519(e, P). Chi conosce la password calcola lo stesso
 *    segreto come X25519(d, E). Dal segreto, con HKDF-SHA256, nasce la chiave AES-GCM.
 *    Così per pubblicare un aggiornamento basta P: la password non serve e non è salvata da
 *    nessuna parte.
 *
 * sito.bin = "GPS1" | iterazioni (u32) | sale (16) | E (32) | iv (12) | dati cifrati
 * I primi 68 byte sono anche "dati autenticati": se qualcuno li cambia, la decifratura fallisce.
 * I dati cifrati sono un JSON compresso con gzip: { file: { percorso: { tipo, testo | b64 } }, pubblici }.
 */
(function (root) {
  'use strict';

  const MAGIA = 'GPS1';
  const LUNGHEZZA_INTESTAZIONE = 68;
  const INFO = 'giochi-pianoforte/sito/1';
  const DB = 'giochi-pianoforte-accesso';
  const STORE = 'stato';
  const PREFISSO_CACHE = 'gp-sito-';
  const te = new TextEncoder();

  // ---------- X25519 (RFC 7748), con BigInt ----------

  const P = 2n ** 255n - 19n;
  const A24 = 121665n;
  const BASE = new Uint8Array(32);
  BASE[0] = 9;

  const mod = (a) => {
    const r = a % P;
    return r < 0n ? r + P : r;
  };

  function potenza(b, e) {
    let r = 1n;
    b = mod(b);
    while (e > 0n) {
      if (e & 1n) r = mod(r * b);
      b = mod(b * b);
      e >>= 1n;
    }
    return r;
  }

  function daLittleEndian(byte) {
    let n = 0n;
    for (let i = byte.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(byte[i]);
    return n;
  }

  function aLittleEndian(n) {
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      out[i] = Number(n & 255n);
      n >>= 8n;
    }
    return out;
  }

  function x25519(scalare, punto) {
    const k = Uint8Array.from(scalare);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    const kn = daLittleEndian(k);
    const u = Uint8Array.from(punto);
    u[31] &= 127;
    const x1 = mod(daLittleEndian(u));

    let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n, scambia = 0n;
    for (let t = 254n; t >= 0n; t--) {
      const bit = (kn >> t) & 1n;
      scambia ^= bit;
      if (scambia) {
        [x2, x3] = [x3, x2];
        [z2, z3] = [z3, z2];
      }
      scambia = bit;
      const A = mod(x2 + z2), AA = mod(A * A);
      const B = mod(x2 - z2), BB = mod(B * B);
      const E = mod(AA - BB);
      const C = mod(x3 + z3), D = mod(x3 - z3);
      const DA = mod(D * A), CB = mod(C * B);
      x3 = mod((DA + CB) * (DA + CB));
      z3 = mod(x1 * mod((DA - CB) * (DA - CB)));
      x2 = mod(AA * BB);
      z2 = mod(E * mod(AA + A24 * E));
    }
    if (scambia) {
      [x2, x3] = [x3, x2];
      [z2, z3] = [z3, z2];
    }
    return aLittleEndian(mod(x2 * potenza(z2, P - 2n)));
  }

  // ---------- Chiavi ----------

  // Maiuscole e spazi non contano: dal telefono è facile sbagliarli.
  function normalizza(password) {
    return String(password).normalize('NFC').trim().replace(/\s+/g, ' ').toLocaleLowerCase('it');
  }

  async function privataDaPassword(password, sale, iterazioni) {
    const base = await crypto.subtle.importKey('raw', te.encode(normalizza(password)), 'PBKDF2', false, ['deriveBits']);
    const bit = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: sale, iterations: iterazioni }, base, 256);
    return new Uint8Array(bit);
  }

  const pubblicaDa = (privata) => x25519(privata, BASE);

  async function chiaveAES(segreto, effimera, pubblica, usi) {
    const materiale = await crypto.subtle.importKey('raw', segreto, 'HKDF', false, ['deriveKey']);
    const sale = new Uint8Array(64);
    sale.set(effimera, 0);
    sale.set(pubblica, 32);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: sale, info: te.encode(INFO) },
      materiale,
      { name: 'AES-GCM', length: 256 },
      false,
      usi,
    );
  }

  // ---------- Formato di sito.bin ----------

  function intestazione(buffer) {
    const b = new Uint8Array(buffer);
    const magia = String.fromCharCode(b[0], b[1], b[2], b[3]);
    if (b.length < LUNGHEZZA_INTESTAZIONE + 16 || magia !== MAGIA) throw errore('formato', 'sito.bin non valido');
    return {
      iterazioni: new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(4),
      sale: b.slice(8, 24),
      effimera: b.slice(24, 56),
      iv: b.slice(56, 68),
      autenticati: b.slice(0, LUNGHEZZA_INTESTAZIONE),
      cifrati: b.slice(LUNGHEZZA_INTESTAZIONE),
    };
  }

  async function decifra(int, privata) {
    const chiave = await chiaveAES(x25519(privata, int.effimera), int.effimera, pubblicaDa(privata), ['decrypt']);
    let chiaro;
    try {
      chiaro = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: int.iv, additionalData: int.autenticati }, chiave, int.cifrati);
    } catch {
      throw errore('password', 'Password sbagliata');
    }
    const flusso = new Blob([chiaro]).stream().pipeThrough(new DecompressionStream('gzip'));
    return JSON.parse(await new Response(flusso).text());
  }

  // ---------- Utilità ----------

  function errore(codice, messaggio) {
    const e = new Error(messaggio);
    e.codice = codice;
    return e;
  }

  const esadecimale = (buf) => Array.from(new Uint8Array(buf), (x) => x.toString(16).padStart(2, '0')).join('');

  const uguali = (a, b) => a && b && a.length === b.length && a.every((x, i) => x === b[i]);

  function daBase64(s) {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ---------- Stato salvato sul dispositivo (IndexedDB) ----------

  function apriDB() {
    return new Promise((ok, ko) => {
      const r = indexedDB.open(DB, 1);
      r.onupgradeneeded = () => r.result.createObjectStore(STORE);
      r.onsuccess = () => ok(r.result);
      r.onerror = () => ko(r.error);
    });
  }

  async function operazione(modo, fai) {
    const db = await apriDB();
    try {
      return await new Promise((ok, ko) => {
        const t = db.transaction(STORE, modo);
        const r = fai(t.objectStore(STORE));
        t.oncomplete = () => ok(r && r.result);
        t.onerror = () => ko(t.error);
        t.onabort = () => ko(t.error);
      });
    } finally {
      db.close();
    }
  }

  const leggi = async () => (await operazione('readonly', (s) => s.get('accesso'))) || null;
  const scrivi = (stato) => operazione('readwrite', (s) => (stato ? s.put(stato, 'accesso') : s.delete('accesso')));

  // ---------- Scaricare e installare ----------

  async function scarica(base) {
    let versione, buffer;
    try {
      const v = await fetch(new URL('versione.json', base), { cache: 'no-store' });
      if (!v.ok) throw new Error(v.status);
      versione = (await v.json()).versione;
      const r = await fetch(new URL('sito.bin?v=' + encodeURIComponent(versione), base), { cache: 'no-store' });
      if (!r.ok) throw new Error(r.status);
      buffer = await r.arrayBuffer();
    } catch {
      throw errore('rete', 'Non riesco a scaricare il sito');
    }
    // Se il file è a metà (rete instabile, pubblicazione in corso) lo scarto e riprovo più tardi.
    const impronta = esadecimale(await crypto.subtle.digest('SHA-256', buffer)).slice(0, 16);
    if (impronta !== versione) throw errore('rete', 'Versione incompleta');
    return { buffer, versione };
  }

  async function installa(pacchetto, base, versione) {
    const nome = PREFISSO_CACHE + versione;
    await caches.delete(nome);
    const cache = await caches.open(nome);
    await Promise.all(Object.entries(pacchetto.file).map(([percorso, f]) => {
      const corpo = f.b64 != null ? daBase64(f.b64) : f.testo;
      return cache.put(new URL(percorso, base).href, new Response(corpo, { headers: { 'Content-Type': f.tipo } }));
    }));
    // Icone e font non sono cifrati: li salvo anche loro, così il sito funziona offline.
    await Promise.all((pacchetto.pubblici || []).map(async (percorso) => {
      try {
        const url = new URL(percorso, base).href;
        const r = await fetch(url, { cache: 'no-cache' });
        if (r.ok) await cache.put(url, r);
      } catch { /* pazienza: verrà dalla rete */ }
    }));
    return nome;
  }

  async function pulisci(tieni) {
    const nomi = await caches.keys();
    await Promise.all(nomi.filter((n) => n.startsWith(PREFISSO_CACHE) && !tieni.includes(n)).map((n) => caches.delete(n)));
  }

  // Prima volta: dalla pagina della password.
  async function entra(password, base) {
    const { buffer, versione } = await scarica(base);
    const int = intestazione(buffer);
    const privata = await privataDaPassword(password, int.sale, int.iterazioni);
    const pacchetto = await decifra(int, privata);
    const cache = await installa(pacchetto, base, versione);
    await scrivi({ privata, sale: int.sale, versione, cache });
    await pulisci([cache]);
  }

  // Dal service worker: se c'è una versione nuova la scarica e la decifra con la chiave salvata.
  // Se la password è cambiata, cancella tutto: alla prossima apertura il sito la chiede di nuovo.
  async function aggiorna(base) {
    const stato = await leggi();
    if (!stato || stato.revocato) return 'fuori';
    const v = await fetch(new URL('versione.json', base), { cache: 'no-store' });
    if (!v.ok) return 'offline';
    if ((await v.json()).versione === stato.versione) return 'uguale';
    const { buffer, versione } = await scarica(base);
    const int = intestazione(buffer);
    let pacchetto = null;
    if (uguali(int.sale, stato.sale)) {
      try {
        pacchetto = await decifra(int, stato.privata);
      } catch (e) {
        if (e.codice !== 'password') throw e;
      }
    }
    if (!pacchetto) {
      // Butto la chiave subito. La pagina già aperta finisce di caricarsi con la copia
      // vecchia; dalla prossima il sito chiede la password nuova.
      await scrivi({ revocato: true, cache: stato.cache });
      return 'uscito';
    }
    const cache = await installa(pacchetto, base, versione);
    await scrivi({ ...stato, versione, cache });
    await pulisci([cache, stato.cache]); // la precedente resta finché non arriva la successiva
    return 'aggiornato';
  }

  async function esci() {
    await scrivi(null);
    await pulisci([]);
  }

  // Il sito è già aperto su questo dispositivo?
  async function aperto(base) {
    const stato = await leggi().catch(() => null);
    if (!stato || stato.revocato) return false;
    return Boolean(await caches.match(new URL('index.html', base).href, { cacheName: stato.cache }));
  }

  root.GP = {
    MAGIA, LUNGHEZZA_INTESTAZIONE, BASE,
    x25519, pubblicaDa, normalizza, privataDaPassword, chiaveAES, intestazione, decifra, esadecimale,
    leggi, entra, aggiorna, esci, aperto,
  };
})(typeof self !== 'undefined' ? self : globalThis);
