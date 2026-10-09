/**
 * Minimal protobuf wire-format reader, scoped to what CRX3's header needs:
 * flat messages made of varint and length-delimited (wire type 2) fields.
 * Not a general protobuf implementation — just enough to read/skip the
 * handful of field shapes CrxFileHeader and SignedData actually use.
 */
export function readFields(buf) {
  const fields = {};
  let i = 0;

  while (i < buf.length) {
    const [tag, tagLen] = readVarint(buf, i);
    i += tagLen;
    const fieldNumber = tag >>> 3;
    const wireType = tag & 0x7;

    let value;
    if (wireType === 0) {
      const [v, len] = readVarint(buf, i);
      value = v;
      i += len;
    } else if (wireType === 2) {
      const [len, lenLen] = readVarint(buf, i);
      i += lenLen;
      value = buf.subarray(i, i + len);
      i += len;
    } else if (wireType === 1) {
      value = buf.subarray(i, i + 8);
      i += 8;
    } else if (wireType === 5) {
      value = buf.subarray(i, i + 4);
      i += 4;
    } else {
      throw new Error(`protobuf-lite: unsupported wire type ${wireType} for field ${fieldNumber}`);
    }

    (fields[fieldNumber] ??= []).push(value);
  }

  return fields;
}

function readVarint(buf, offset) {
  let result = 0n;
  let shift = 0n;
  let i = offset;
  for (;;) {
    const byte = buf[i++];
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7n;
  }
  return [Number(result), i - offset];
}
