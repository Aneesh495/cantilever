import crypto from "crypto";

export function generateRandomNonceRaw() {
  return crypto.randomBytes(16).toString("base64url");
}

export function getCurrentTimeMillis() {
  return Date.now();
}
