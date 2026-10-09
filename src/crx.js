// A CRX file is a signed ZIP: a small header (signatures/public keys)
// prepended to an ordinary ZIP archive.
//
// CRX3: "Cr24" | uint32le version=3 | uint32le headerLen | header | ZIP
// CRX2: "Cr24" | uint32le version=2 | uint32le keyLen | uint32le sigLen | key | sig | ZIP

import { createHash, createVerify } from 'node:crypto';
import { readFields } from './protobuf-lite.js';

const MAGIC = 'Cr24';
const ZIP_MAGIC = 0x04034b50;

/**
 * Strip the CRX header and return the embedded ZIP as a Buffer.
 * Also accepts a plain ZIP (some mirrors serve unwrapped archives).
 */
export function crxToZip(buf) {
  if (buf.length >= 4 && buf.readUInt32LE(0) === ZIP_MAGIC) {
    return buf; // already a plain ZIP
  }

  if (buf.length < 16 || buf.toString('latin1', 0, 4) !== MAGIC) {
    throw new Error('Not a CRX file (missing Cr24 magic). The store may have returned an error page.');
  }

  const version = buf.readUInt32LE(4);
  let zipStart;

  if (version === 3) {
    const headerLen = buf.readUInt32LE(8);
    zipStart = 12 + headerLen;
  } else if (version === 2) {
    const keyLen = buf.readUInt32LE(8);
    const sigLen = buf.readUInt32LE(12);
    zipStart = 16 + keyLen + sigLen;
  } else {
    throw new Error(`Unsupported CRX version: ${version}`);
  }

  if (zipStart >= buf.length) {
    throw new Error('Corrupt CRX: header extends past end of file.');
  }

  const zip = buf.subarray(zipStart);
  if (zip.readUInt32LE(0) !== ZIP_MAGIC) {
    throw new Error('Corrupt CRX: no ZIP archive found after header.');
  }
  return zip;
}

// Per crx3.proto's own comment on signed_header_data: the signed value is
// "CRX3 SignedData\x00" + signed_header_size (4 bytes, little-endian) +
// signed_header_data + archive. Confirmed 2026-10-09 against a real
// extension's CRX3 (React Developer Tools) — the magic alone (no NUL, no
// size prefix) does not verify; this exact construction does.
const CRX3_SIGNED_DATA_MAGIC = Buffer.from('CRX3 SignedData\0', 'ascii');
const ID_ALPHABET = 'abcdefghijklmnop';

// CrxFileHeader field numbers, confirmed against crxviewer's independent
// implementation (src/lib/crx-to-zip.js, getPublicKeyFromProtoBuf): field 2
// is the repeated sha256_with_rsa proof, field 10000 is signed_header_data.
// Inside AsymmetricKeyProof: field 1 is public_key, field 2 is signature.
// Inside SignedData: field 1 is crx_id.
const FIELD_SHA256_WITH_RSA = 2;
const FIELD_SIGNED_HEADER_DATA = 10000;

/**
 * Parse a CRX3 file's signature block and verify each embedded RSA proof.
 * Returns { verified, extensionId, reason }; `verified` is true only if at
 * least one proof's signature checks out AND its derived extension ID
 * matches `expectedId`.
 */
export function verifyCrx3Signature(buf, expectedId) {
  if (buf.length < 12 || buf.toString('latin1', 0, 4) !== MAGIC || buf.readUInt32LE(4) !== 3) {
    return { verified: false, extensionId: null, reason: 'not a CRX3 file' };
  }

  const headerLen = buf.readUInt32LE(8);
  const header = buf.subarray(12, 12 + headerLen);
  const zip = buf.subarray(12 + headerLen);

  const top = readFields(header);
  const signedHeaderData = top[FIELD_SIGNED_HEADER_DATA]?.[0];
  if (!signedHeaderData) {
    return { verified: false, extensionId: null, reason: 'missing signed_header_data' };
  }

  const signedDataFields = readFields(signedHeaderData);
  const crxIdBytes = signedDataFields[1]?.[0];
  const extensionId = crxIdBytes ? bytesToExtensionId(crxIdBytes) : null;

  const signedHeaderSize = Buffer.alloc(4);
  signedHeaderSize.writeUInt32LE(signedHeaderData.length, 0);
  const signedPayload = Buffer.concat([CRX3_SIGNED_DATA_MAGIC, signedHeaderSize, signedHeaderData, zip]);

  const rsaProofs = (top[FIELD_SHA256_WITH_RSA] ?? []).map((p) => readFields(p));
  for (const proof of rsaProofs) {
    const publicKeyDer = proof[1]?.[0];
    const signature = proof[2]?.[0];
    if (!publicKeyDer || !signature) continue;

    try {
      const derivedId = bytesToExtensionId(createHash('sha256').update(publicKeyDer).digest().subarray(0, 16));
      const verifier = createVerify('RSA-SHA256');
      verifier.update(signedPayload);
      const sigOk = verifier.verify({ key: publicKeyDer, format: 'der', type: 'spki' }, signature);

      if (sigOk && derivedId === expectedId) {
        return { verified: true, extensionId: derivedId, reason: null };
      }
    } catch {
      // Malformed or unsupported proof (e.g. bad DER) — treat it as a
      // failed proof and keep checking the rest; real CRX3s often carry
      // more than one, and one bad entry shouldn't sink a good one.
      continue;
    }
  }

  return {
    verified: false,
    extensionId,
    reason: rsaProofs.length ? 'signature or ID mismatch' : 'no RSA proof found in header',
  };
}

function bytesToExtensionId(bytes) {
  let id = '';
  for (const byte of bytes) {
    id += ID_ALPHABET[(byte >> 4) & 0xf];
    id += ID_ALPHABET[byte & 0xf];
  }
  return id.slice(0, 32);
}
