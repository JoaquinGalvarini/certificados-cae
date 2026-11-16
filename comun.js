// Funciones compartidas entre index.html (público) y admin.html (carga de datos).
// La lista de habilitados no se publica en texto plano: cada registro se guarda
// bajo una clave derivada del DNI y el nombre va cifrado con ese mismo DNI.
(function () {
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const unhex = (s) => new Uint8Array(s.match(/.{2}/g).map((h) => parseInt(h, 16)));

  function b64(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function unb64(s) {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // "12.345.678" -> "12345678". Devuelve "" si no parece un DNI.
  function normalizarDni(texto) {
    const d = String(texto || "").replace(/\D/g, "").replace(/^0+/, "");
    return d.length >= 6 && d.length <= 9 ? d : "";
  }

  function formatearDni(dni) {
    return dni.replace(/\B(?=(\d{3})+(?!\d))/g, ".");
  }

  function limpiarNombre(texto) {
    return String(texto || "").replace(/\s+/g, " ").trim().toLocaleUpperCase("es");
  }

  // Palabras del nombre sin acentos, para comparar lo tipeado con la lista.
  function palabras(nombre) {
    return limpiarNombre(nombre)
      .normalize("NFD")
      .replace(/[̀-ͯ]/g, "")
      .split(/[^A-Z]+/)
      .filter((p) => p.length >= 3);
  }

  function nombresCoinciden(a, b) {
    const pa = new Set(palabras(a));
    return palabras(b).some((p) => pa.has(p));
  }

  async function derivar(dni, salHex, iter) {
    const base = await crypto.subtle.importKey("raw", enc.encode(dni), "PBKDF2", false, ["deriveBits"]);
    const bits = new Uint8Array(
      await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-512", salt: unhex(salHex), iterations: iter }, base, 384)
    );
    const clave = await crypto.subtle.importKey("raw", bits.slice(16, 48), "AES-GCM", false, ["encrypt", "decrypt"]);
    return { id: hex(bits.slice(0, 12)), clave };
  }

  async function cifrarRegistro(dni, nombre, salHex, iter) {
    const { id, clave } = await derivar(dni, salHex, iter);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, clave, enc.encode(nombre)));
    const todo = new Uint8Array(iv.length + ct.length);
    todo.set(iv);
    todo.set(ct, iv.length);
    return [id, b64(todo)];
  }

  // Devuelve null si el DNI no está en la lista; si está, el nombre cargado ("" si no se cargó nombre).
  async function buscarHabilitado(dni, lista) {
    const { id, clave } = await derivar(dni, lista.sal, lista.iter);
    const reg = lista.reg[id];
    if (reg === undefined) return null;
    const datos = unb64(reg);
    const claro = await crypto.subtle.decrypt({ name: "AES-GCM", iv: datos.slice(0, 12) }, clave, datos.slice(12));
    return dec.decode(claro);
  }

  window.CAE = { hex, b64, unb64, normalizarDni, formatearDni, limpiarNombre, nombresCoinciden, cifrarRegistro, buscarHabilitado };
})();
