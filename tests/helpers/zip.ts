import { deflateRawSync } from 'node:zlib';

/** Minimal ZIP writer for tests: stored or deflated entries, optional "encrypted" flag. */
export function makeZip(files: Array<{ name: string; data: Uint8Array | string; deflate?: boolean; encrypted?: boolean }>): Uint8Array {
  const enc = new TextEncoder();
  const locals: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  for (const f of files) {
    const raw = typeof f.data === 'string' ? enc.encode(f.data) : f.data;
    const body = f.deflate ? new Uint8Array(deflateRawSync(raw)) : raw;
    const name = enc.encode(f.name);
    const flags = f.encrypted ? 1 : 0;
    const method = f.deflate ? 8 : 0;
    const local = new Uint8Array(30 + name.length + body.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, flags, true);
    lv.setUint16(8, method, true);
    lv.setUint32(18, body.length, true);
    lv.setUint32(22, raw.length, true);
    lv.setUint16(26, name.length, true);
    local.set(name, 30);
    local.set(body, 30 + name.length);
    const cd = new Uint8Array(46 + name.length);
    const cv = new DataView(cd.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, flags, true);
    cv.setUint16(10, method, true);
    cv.setUint32(20, body.length, true);
    cv.setUint32(24, raw.length, true);
    cv.setUint16(28, name.length, true);
    cv.setUint32(42, offset, true);
    cd.set(name, 46);
    locals.push(local);
    central.push(cd);
    offset += local.length;
  }
  const cdSize = central.reduce((a, c) => a + c.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, files.length, true);
  ev.setUint16(10, files.length, true);
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, offset, true);
  const out = new Uint8Array(offset + cdSize + 22);
  let p = 0;
  for (const part of [...locals, ...central, eocd]) {
    out.set(part, p);
    p += part.length;
  }
  return out;
}

/** UTF-16LE string bytes, as found in compiled AndroidManifest.xml string pools. */
export function utf16(s: string): Uint8Array {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) out[i * 2] = s.charCodeAt(i);
  return out;
}

/** A tiny PE header: MZ, e_lfanew, PE\0\0, optional header with/without a certificate table. */
export function makePe(signed: boolean): Uint8Array {
  const b = new Uint8Array(512);
  const v = new DataView(b.buffer);
  b[0] = 0x4d;
  b[1] = 0x5a;
  v.setUint32(0x3c, 0x80, true);
  v.setUint32(0x80, 0x00004550, true);
  const opt = 0x80 + 24;
  v.setUint16(opt, 0x20b, true); // PE32+
  v.setUint32(opt + 108, 16, true); // NumberOfRvaAndSizes
  if (signed) {
    v.setUint32(opt + 112 + 32, 0x100, true);
    v.setUint32(opt + 112 + 36, 0x40, true);
  }
  return b;
}
