// Cantilever.Core.ASN1.PEM FFI implementation
// Base64 encoding/decoding
export const base64EncodeImpl = function(bytes) {
  return Buffer.from(bytes).toString("base64");
};

export const base64DecodeImpl = function(just, nothing, str) {
  try {
    const clean = str.replace(/[\r\n\s]/g, "");
    const buf = Buffer.from(clean, "base64");
    return just(Array.from(buf));
  } catch (e) {
    return nothing;
  }
};
