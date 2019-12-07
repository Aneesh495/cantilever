// Cantilever.Core.Crypto.AEAD FFI implementation
// Authenticated Encryption with Associated Data (AES-256-GCM)
import crypto from "node:crypto";

export const encryptAesGcmImpl = function(keyBytes, ivBytes, plaintextBytes, aadBytes) {
  const key = Buffer.from(keyBytes);
  const iv = Buffer.from(ivBytes);
  const plaintext = Buffer.from(plaintextBytes);
  const aad = Buffer.from(aadBytes);

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  if (aad.length > 0) {
    cipher.setAAD(aad);
  }
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    ciphertext: Array.from(ciphertext),
    tag: Array.from(tag)
  };
};

export const decryptAesGcmImpl = function(just, nothing, keyBytes, ivBytes, ciphertextBytes, tagBytes, aadBytes) {
  try {
    const key = Buffer.from(keyBytes);
    const iv = Buffer.from(ivBytes);
    const ciphertext = Buffer.from(ciphertextBytes);
    const tag = Buffer.from(tagBytes);
    const aad = Buffer.from(aadBytes);

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    if (aad.length > 0) {
      decipher.setAAD(aad);
    }
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return just(Array.from(plaintext));
  } catch (e) {
    return nothing;
  }
};

export const pbkdf2Impl = function(passphrase, saltBytes, iterations, keyLen) {
  const salt = Buffer.from(saltBytes);
  const derived = crypto.pbkdf2Sync(passphrase, salt, iterations, keyLen, "sha256");
  return Array.from(derived);
};
