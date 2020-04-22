export function base64urlDecodeToBytes(b64urlStr) {
  try {
    const buf = Buffer.from(b64urlStr, "base64url");
    return Array.from(buf);
  } catch (e) {
    return [];
  }
}

export function base64urlDecodeToString(b64urlStr) {
  try {
    return Buffer.from(b64urlStr, "base64url").toString("utf8");
  } catch (e) {
    return "";
  }
}

export function base64urlEncodeBytes(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

export function base64urlEncodeString(str) {
  return Buffer.from(str, "utf8").toString("base64url");
}

export function stringToUtf8Bytes(str) {
  return Array.from(Buffer.from(str, "utf8"));
}

export function utf8BytesToString(bytes) {
  return Buffer.from(bytes).toString("utf8");
}
