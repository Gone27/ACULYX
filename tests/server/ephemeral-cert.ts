/**
 * @file ephemeral-cert.ts
 * Generates an ephemeral in-memory self-signed X.509 v3 certificate for localhost / 127.0.0.1
 * test servers without committing any static private key or certificate files to the repository.
 */

import crypto from 'node:crypto';

function encodeLen(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derTlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLen(content.length), content]);
}

function derSeq(items: Buffer[]): Buffer {
  return derTlv(0x30, Buffer.concat(items));
}

function derSet(items: Buffer[]): Buffer {
  return derTlv(0x31, Buffer.concat(items));
}

function derInt(value: number | Buffer): Buffer {
  let buf = typeof value === 'number' ? Buffer.from([value]) : value;
  if (buf.length === 0) buf = Buffer.from([0]);
  if ((buf[0] ?? 0) & 0x80) {
    buf = Buffer.concat([Buffer.from([0]), buf]);
  }
  return derTlv(0x02, buf);
}

function derOid(oidStr: string): Buffer {
  const parts = oidStr.split('.').map((p) => parseInt(p, 10));
  const out: number[] = [(parts[0] ?? 0) * 40 + (parts[1] ?? 0)];
  for (let i = 2; i < parts.length; i++) {
    let val = parts[i] ?? 0;
    const chunks: number[] = [val & 0x7f];
    val >>= 7;
    while (val > 0) {
      chunks.unshift((val & 0x7f) | 0x80);
      val >>= 7;
    }
    out.push(...chunks);
  }
  return derTlv(0x06, Buffer.from(out));
}

function derBitString(buf: Buffer): Buffer {
  return derTlv(0x03, Buffer.concat([Buffer.from([0]), buf]));
}

function derUtf8(str: string): Buffer {
  return derTlv(0x0c, Buffer.from(str, 'utf8'));
}

function derGeneralizedTime(date: Date): Buffer {
  const iso = date.toISOString().replace(/[-:T]/g, '').slice(0, 14) + 'Z';
  return derTlv(0x18, Buffer.from(iso, 'ascii'));
}

function toPem(label: string, der: Buffer): string {
  const b64 = der.toString('base64').replace(/.{1,64}/g, '$&\n').trimEnd();
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

export interface EphemeralTlsMaterial {
  key: string;
  cert: string;
}

/** Generate a fresh 2048-bit RSA self-signed certificate valid for 127.0.0.1 and localhost. */
export function createEphemeralTestCert(): EphemeralTlsMaterial {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });

  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

  // sha256WithRSAEncryption OID 1.2.840.113549.1.1.11
  const sigAlg = derSeq([derOid('1.2.840.113549.1.1.11'), Buffer.from([0x05, 0x00])]);
  // Subject/Issuer: CN=127.0.0.1 (OID 2.5.4.3)
  const name = derSeq([derSet([derSeq([derOid('2.5.4.3'), derUtf8('127.0.0.1')])])]);

  const now = new Date(Date.now() - 60_000);
  const expires = new Date(Date.now() + 86_400_000);
  const validity = derSeq([derGeneralizedTime(now), derGeneralizedTime(expires)]);

  // SubjectAltName (OID 2.5.29.17): dNSName(2) "localhost", iPAddress(7) 127.0.0.1
  const sanValue = derSeq([
    derTlv(0x82, Buffer.from('localhost', 'ascii')),
    derTlv(0x87, Buffer.from([127, 0, 0, 1])),
  ]);
  const sanExt = derSeq([derOid('2.5.29.17'), derTlv(0x04, sanValue)]);
  const extensions = derTlv(0xa3, derSeq([sanExt]));

  const serial = crypto.randomBytes(8);
  serial[0] = (serial[0] ?? 1) & 0x7f;

  const tbsCert = derSeq([
    derTlv(0xa0, derInt(2)), // v3
    derInt(serial),
    sigAlg,
    name,
    validity,
    name,
    spkiDer,
    extensions,
  ]);

  const signature = crypto.sign('sha256', tbsCert, privateKey);
  const certDer = derSeq([tbsCert, sigAlg, derBitString(signature)]);

  return {
    key: keyPem,
    cert: toPem('CERTIFICATE', certDer),
  };
}
