// Cantilever.Core.Crypto.Shamir FFI implementation
import crypto from "node:crypto";

export const randomBytesImpl = function(count) {
  return function() {
    const buf = crypto.randomBytes(count);
    return Array.from(buf);
  };
};
