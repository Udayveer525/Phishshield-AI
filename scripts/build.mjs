// Production build for the extension (dist/extension) and the optional API server (dist/server).
//   node scripts/build.mjs [--only=extension|server]
import { build } from 'esbuild';
import { cp, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const only = process.argv.find((a) => a.startsWith('--only='))?.slice('--only='.length);
const src = join(root, 'src/extension');
const out = join(root, 'dist/extension');

async function buildExtension() {
  await rm(out, { recursive: true, force: true });
  const common = { bundle: true, target: 'chrome120', platform: 'browser', legalComments: 'none', logLevel: 'warning', define: { 'process.env.NODE_ENV': '"production"' } };
  await build({
    ...common,
    format: 'esm',
    entryPoints: ['background.ts', 'popup/popup.ts', 'warning/warning.ts', 'options/options.ts', 'download/download.ts', 'center/center.ts'].map((f) => join(src, f)),
    outdir: out,
    outbase: src,
  });
  // Content scripts registered via chrome.scripting cannot be modules.
  await build({ ...common, format: 'iife', entryPoints: [join(src, 'content/guard.ts')], outfile: join(out, 'content/guard.js') });

  for (const f of await listFiles(src)) {
    if (/\.(html|css|json)$/.test(f)) {
      await mkdir(dirname(join(out, f)), { recursive: true });
      await cp(join(src, f), join(out, f));
    }
  }
  await mkdir(join(out, 'icons'), { recursive: true });
  for (const size of [16, 32, 48, 128]) await writeFile(join(out, `icons/icon${size}.png`), shieldPng(size));

  await assertNoSecrets(out);
  console.info(`extension → ${relative(root, out)}`);
}

async function buildServer() {
  await rm(join(root, 'dist/server'), { recursive: true, force: true });
  await build({
    entryPoints: [join(root, 'src/server/index.ts')],
    outfile: join(root, 'dist/server/index.js'),
    bundle: true,
    platform: 'node',
    target: 'node20',
    format: 'esm',
    packages: 'external',
    logLevel: 'warning',
  });
  console.info('server → dist/server/index.js');
}

async function listFiles(dir, base = dir) {
  const result = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) result.push(...(await listFiles(p, base)));
    else result.push(relative(base, p));
  }
  return result;
}

// Fails the build if anything resembling a provider credential ended up in the extension bundle.
async function assertNoSecrets(dir) {
  const patterns = [/gsk_[A-Za-z0-9]{20,}/, /sk-ant-[A-Za-z0-9_-]{10,}/, /AIza[0-9A-Za-z_-]{35}/, /(?:GROQ|ANTHROPIC|GSB|VT)_API_KEY\s*[:=]\s*['"][^'"]+/];
  for (const f of await listFiles(dir)) {
    if (!/\.(js|html|json|css)$/.test(f)) continue;
    const text = await readFile(join(dir, f), 'utf8');
    const hit = patterns.find((p) => p.test(text));
    if (hit) throw new Error(`Possible secret in extension bundle: ${f} (${hit})`);
  }
}

// --- Icon generation: a teal shield with a check mark, rendered with 4x4 supersampling. ---

function shieldCoverage(x, y) {
  // Normalised coordinates in [0, 1].
  if (y < 0.08 || y > 0.94) return { shield: false, check: false };
  const t = y <= 0.48 ? 0 : (y - 0.48) / 0.46;
  const half = 0.36 * (1 - t * t);
  const shield = Math.abs(x - 0.5) <= half;
  const d = Math.min(segDist(x, y, 0.33, 0.5, 0.46, 0.64), segDist(x, y, 0.46, 0.64, 0.69, 0.36));
  return { shield, check: shield && d < 0.06 };
}

function segDist(px, py, ax, ay, bx, by) {
  const dx = bx - ax;
  const dy = by - ay;
  const k = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (ax + k * dx), py - (ay + k * dy));
}

function shieldPng(size) {
  const ss = 4;
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    for (let x = 0; x < size; x++) {
      let fill = 0;
      let check = 0;
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const c = shieldCoverage((x + (sx + 0.5) / ss) / size, (y + (sy + 0.5) / ss) / size);
          if (c.shield) fill++;
          if (c.check) check++;
        }
      }
      const n = ss * ss;
      const a = fill / n;
      const w = fill ? check / fill : 0;
      const i = y * (size * 4 + 1) + 1 + x * 4;
      raw[i] = Math.round(0x0e + (255 - 0x0e) * w);
      raw[i + 1] = Math.round(0x74 + (255 - 0x74) * w);
      raw[i + 2] = Math.round(0x90 + (255 - 0x90) * w);
      raw[i + 3] = Math.round(a * 255);
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr.set([8, 6, 0, 0, 0], 8);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function chunk(type, data) {
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  let c = 0xffffffff;
  for (const b of body) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE((c ^ 0xffffffff) >>> 0);
  return Buffer.concat([len, body, crc]);
}

if (!only || only === 'extension') await buildExtension();
if (!only || only === 'server') await buildServer();
