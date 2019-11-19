// Cantilever.Core.Crypto.BigInt FFI implementation
// Provides native JavaScript BigInt bindings for arbitrary precision integer arithmetic

export const fromIntImpl = function(n) {
  return BigInt(n);
};

export const fromStringImpl = function(just, nothing, str) {
  try {
    const s = str.trim();
    if (s.startsWith("0x") || s.startsWith("0X")) {
      return just(BigInt(s));
    }
    return just(BigInt(s));
  } catch (e) {
    return nothing;
  }
};

export const toStringImpl = function(radix, b) {
  return b.toString(radix);
};

export const addImpl = function(a, b) {
  return a + b;
};

export const subImpl = function(a, b) {
  return a - b;
};

export const mulImpl = function(a, b) {
  return a * b;
};

export const divImpl = function(a, b) {
  if (b === 0n) return 0n;
  return a / b;
};

export const modImpl = function(a, b) {
  if (b === 0n) return 0n;
  return a % b;
};

export const eqImpl = function(a, b) {
  return a === b;
};

export const compareImpl = function(lt, eq, gt, a, b) {
  if (a < b) return lt;
  if (a > b) return gt;
  return eq;
};

export const powModImpl = function(base, exp, mod) {
  if (mod === 1n) return 0n;
  let b = base % mod;
  let e = exp;
  let m = mod;
  let result = 1n;
  while (e > 0n) {
    if (e % 2n === 1n) {
      result = (result * b) % m;
    }
    e = e / 2n;
    b = (b * b) % m;
  }
  return result;
};

export const toOctetsImpl = function(b) {
  let hex = b.toString(16);
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return bytes;
};

export const fromOctetsImpl = function(octets) {
  let result = 0n;
  for (let i = 0; i < octets.length; i++) {
    result = (result << 8n) | BigInt(octets[i] & 0xff);
  }
  return result;
};

export const bitLengthImpl = function(b) {
  if (b === 0n) return 0;
  let val = b < 0n ? -b : b;
  let bits = 0;
  while (val > 0n) {
    bits++;
    val = val >> 1n;
  }
  return bits;
};
