/**
 * Offline token integrity checks.
 *
 * Some vendors embed a CRC32 checksum in their token format specifically so scanners can
 * discard random look-alikes without contacting the vendor. A token whose checksum does NOT
 * match is almost certainly not a real credential (strong false-positive signal). A matching
 * checksum proves the string matches the documented vendor specification, but NOT that it is still live
 * or that it was uniquely minted by the vendor.
 */

const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

let crcTable: Uint32Array | undefined;

function getCrcTable(): Uint32Array {
  if (crcTable !== undefined) return crcTable;
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    t[n] = c >>> 0;
  }
  crcTable = t;
  return t;
}

export function crc32(input: string): number {
  const table = getCrcTable();
  let crc = 0xffffffff;
  for (let i = 0; i < input.length; i++) {
    crc = (table[(crc ^ input.charCodeAt(i)) & 0xff] ?? 0) ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function base62Encode(value: number, width: number): string {
  let n = value;
  let out = '';
  while (n > 0) {
    out = (BASE62[n % 62] ?? '0') + out;
    n = Math.floor(n / 62);
  }
  return out.padStart(width, '0');
}

/**
 * GitHub classic tokens (ghp_, gho_, ghu_, ghs_, ghr_) and npm automation tokens (npm_):
 * <prefix>_<30 random base62 chars><6 char base62 CRC32 of the 30 random chars>.
 * Returns undefined when the string is not in that shape (no checksum applicable).
 */
export function validateCrc32Base62Token(token: string): boolean | undefined {
  const m = /^(?:gh[pousr]|npm)_([0-9A-Za-z]{30})([0-9A-Za-z]{6})$/.exec(token);
  if (m === null) return undefined;
  const body = m[1];
  const checksum = m[2];
  if (body === undefined || checksum === undefined) return undefined;
  return base62Encode(crc32(body), 6) === checksum;
}
