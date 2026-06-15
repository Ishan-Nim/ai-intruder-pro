// db.js — IndexedDB backbone for capture volume. Loaded into the service worker
// via importScripts. Exposes self.IDB.
(function () {
  const DB_NAME = "ai_intruder";
  const DB_VERSION = 1;
  let dbp = null;

  function open() {
    if (dbp) return dbp;
    dbp = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains("entries")) db.createObjectStore("entries", { keyPath: "id" });
        if (!db.objectStoreNames.contains("audit")) db.createObjectStore("audit", { keyPath: "id" });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return dbp;
  }

  function tx(store, mode) {
    return open().then((db) => db.transaction(store, mode).objectStore(store));
  }
  function wrap(req) {
    return new Promise((res, rej) => { req.onsuccess = () => res(req.result); req.onerror = () => rej(req.error); });
  }

  self.IDB = {
    async put(store, value) { return wrap((await tx(store, "readwrite")).put(value)); },
    async getAll(store) { return wrap((await tx(store, "readonly")).getAll()); },
    async delete(store, key) { return wrap((await tx(store, "readwrite")).delete(key)); },
    async clear(store) { return wrap((await tx(store, "readwrite")).clear()); },
    async count(store) { return wrap((await tx(store, "readonly")).count()); },
    // keep newest N: delete oldest by ts when over cap
    async trim(store, cap, tsField) {
      const all = await this.getAll(store);
      if (all.length <= cap) return;
      all.sort((a, b) => (a[tsField] || 0) - (b[tsField] || 0));
      const toDelete = all.slice(0, all.length - cap);
      const t = (await open()).transaction(store, "readwrite").objectStore(store);
      toDelete.forEach((e) => t.delete(e.id));
    }
  };
})();
