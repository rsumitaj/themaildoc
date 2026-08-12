/**
 * DKIM public key inspection — RFC 6376 §3.6.1, RFC 8301 §3.2, RFC 8463.
 *
 * Key size is the whole point of this file. "There is a key" is not a finding;
 * "this key is 512 bits and every verifier rejects it" is.
 */

export interface DkimKey {
  algorithm: 'rsa' | 'ed25519';
  /** Modulus size for RSA, 256 for a well-formed Ed25519 key. */
  bits: number;
  valid: boolean;
}

/** Decode base64 that DNS panels have often wrapped in whitespace. */
export function decodeBase64(value: string): Uint8Array | null {
  const cleaned = value.replace(/\s+/g, '');
  if (cleaned === '') return new Uint8Array(0);
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleaned)) return null;

  try {
    const binary = atob(cleaned);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

/**
 * Read the RSA modulus length out of a DER-encoded SubjectPublicKeyInfo.
 *
 * WebCrypto would tell us this directly, but it is async and rejects on keys
 * that are malformed in ways we specifically want to report. Walking the
 * structure ourselves is exact, synchronous, and works identically on workerd,
 * Node and the browser.
 */
export function rsaModulusBits(der: Uint8Array): number | null {
  let offset = 0;

  const readLength = (): number | null => {
    const first = der[offset];
    if (first === undefined) return null;
    offset += 1;
    if (first < 0x80) return first;

    const count = first & 0x7f;
    if (count === 0 || count > 4) return null;
    let length = 0;
    for (let i = 0; i < count; i += 1) {
      const byte = der[offset + i];
      if (byte === undefined) return null;
      length = length * 256 + byte;
    }
    offset += count;
    return length;
  };

  // SEQUENCE { SEQUENCE { OID, params }, BIT STRING { SEQUENCE { INTEGER n, INTEGER e } } }
  if (der[offset] !== 0x30) return null;
  offset += 1;
  if (readLength() === null) return null;

  if (der[offset] !== 0x30) return null;
  offset += 1;
  const algLength = readLength();
  if (algLength === null) return null;
  offset += algLength;

  if (der[offset] !== 0x03) return null; // BIT STRING
  offset += 1;
  if (readLength() === null) return null;
  offset += 1; // unused-bits byte

  if (der[offset] !== 0x30) return null;
  offset += 1;
  if (readLength() === null) return null;

  if (der[offset] !== 0x02) return null; // INTEGER (modulus)
  offset += 1;
  const modulusLength = readLength();
  if (modulusLength === null) return null;

  // ASN.1 prepends a zero byte to keep the integer positive; it is not key material.
  const leadingZero = der[offset] === 0x00 ? 1 : 0;
  return (modulusLength - leadingZero) * 8;
}

/**
 * Inspect the `p=` value of a DKIM record.
 *
 * Returns `null` for an unusable key, `bits: 0` for a revoked one (an empty
 * `p=` is a deliberate revocation, not a mistake).
 */
export function inspectKey(publicKey: string, algorithm: string | undefined): DkimKey | null {
  const kind = (algorithm ?? 'rsa').toLowerCase();
  const bytes = decodeBase64(publicKey);
  if (bytes === null) return null;

  if (kind === 'ed25519') {
    // RFC 8463 §3: the key is the raw 32-byte value, not a SPKI wrapper.
    return { algorithm: 'ed25519', bits: bytes.length * 8, valid: bytes.length === 32 };
  }

  const bits = rsaModulusBits(bytes);
  if (bits === null || bits <= 0) return null;
  return { algorithm: 'rsa', bits, valid: true };
}
