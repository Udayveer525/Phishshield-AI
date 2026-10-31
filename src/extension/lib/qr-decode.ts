import jsQR from 'jsqr';

/**
 * QR decoding with jsQR (Apache-2.0), entirely on the device. Images are drawn to an offscreen
 * canvas; nothing is uploaded. Tries the full image first, then downscaled copies, because jsQR
 * struggles with very large photos and with codes that fill only a small part of a screenshot.
 */

const MAX_SIDE = 1600;

export async function decodeQrFromBlob(blob: Blob): Promise<string | null> {
  const bitmap = await createImageBitmap(blob);
  try {
    return decodeQrFromBitmap(bitmap);
  } finally {
    bitmap.close();
  }
}

export function decodeQrFromBitmap(source: ImageBitmap | HTMLImageElement | HTMLCanvasElement): string | null {
  const w = source.width;
  const h = source.height;
  if (!w || !h) return null;
  const base = Math.min(1, MAX_SIDE / Math.max(w, h));
  for (const scale of [base, base * 0.6, base * 0.35]) {
    const cw = Math.max(1, Math.round(w * scale));
    const ch = Math.max(1, Math.round(h * scale));
    if (cw < 60 || ch < 60) continue;
    const canvas = new OffscreenCanvas(cw, ch);
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) return null;
    ctx.imageSmoothingEnabled = scale < 1;
    ctx.drawImage(source, 0, 0, cw, ch);
    const img = ctx.getImageData(0, 0, cw, ch);
    const code = jsQR(img.data, cw, ch, { inversionAttempts: 'attemptBoth' });
    if (code?.data) return code.data;
  }
  return null;
}

/** Decode a data: URL (from chrome.tabs.captureVisibleTab). */
export async function decodeQrFromDataUrl(dataUrl: string): Promise<string | null> {
  const blob = await (await fetch(dataUrl)).blob();
  return decodeQrFromBlob(blob);
}
