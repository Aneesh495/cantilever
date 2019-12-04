// Cantilever.Core.Crypto.Hash FFI implementation
// Uses Node.js crypto module for cryptographic hashing and HMAC
import crypto from "node:crypto";

export const sha1Impl = function(bytes) {
  const buf = Buffer.from(bytes);
  const hash = crypto.createHash("sha1").update(buf).digest();
  return Array.from(hash);
};

export const sha256Impl = function(bytes) {
  const buf = Buffer.from(bytes);
  const hash = crypto.createHash("sha256").update(buf).digest();
  return Array.from(hash);
};

export const sha384Impl = function(bytes) {
  const buf = Buffer.from(bytes);
  const hash = crypto.createHash("sha384").update(buf).digest();
  return Array.from(hash);
};

export const sha512Impl = function(bytes) {
  const buf = Buffer.from(bytes);
  const hash = crypto.createHash("sha512").update(buf).digest();
  return Array.from(hash);
};

export const md5Impl = function(bytes) {
  const buf = Buffer.from(bytes);
  const hash = crypto.createHash("md5").update(buf).digest();
  return Array.from(hash);
};

export const hmacSha256Impl = function(keyBytes, dataBytes) {
  const key = Buffer.from(keyBytes);
  const data = Buffer.from(dataBytes);
  const mac = crypto.createHmac("sha256", key).update(data).digest();
  return Array.from(mac);
};

export const toHexImpl = function(bytes) {
  return Buffer.from(bytes).toString("hex");
};

export const fromHexImpl = function(just, nothing, hex) {
  try {
    const cleanHex = hex.trim();
    if (cleanHex.length % 2 !== 0) return nothing;
    const buf = Buffer.from(cleanHex, "hex");
    return just(Array.from(buf));
  } catch (e) {
    return nothing;
  }
};
