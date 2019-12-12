// Cantilever.Core.Crypto.Key FFI implementation
// Key generation, JWK thumbprinting, and key format conversions
import crypto from "node:crypto";

export const generateRsaKeyPairImpl = function(bits) {
  return function() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: bits,
      publicKeyEncoding: { type: "spki", format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "der" }
    });
    return {
      publicKeyDer: Array.from(publicKey),
      privateKeyDer: Array.from(privateKey)
    };
  };
};

export const generateEcKeyPairImpl = function(namedCurve) {
  return function() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: namedCurve,
      publicKeyEncoding: { type: "spki", format: "der" },
      privateKeyEncoding: { type: "pkcs8", format: "der" }
    });
    return {
      publicKeyDer: Array.from(publicKey),
      privateKeyDer: Array.from(privateKey)
    };
  };
};

export const generateEd25519KeyPairImpl = function() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" }
  });
  return {
    publicKeyDer: Array.from(publicKey),
    privateKeyDer: Array.from(privateKey)
  };
};

export const jwkThumbprintSha256Impl = function(just, nothing, spkiDerBytes) {
  try {
    const keyObject = crypto.createPublicKey({
      key: Buffer.from(spkiDerBytes),
      format: "der",
      type: "spki"
    });
    const jwk = keyObject.export({ format: "jwk" });
    let canonical = "";
    if (jwk.kty === "RSA") {
      canonical = JSON.stringify({ e: jwk.e, kty: "RSA", n: jwk.n });
    } else if (jwk.kty === "EC") {
      canonical = JSON.stringify({ crv: jwk.crv, kty: "EC", x: jwk.x, y: jwk.y });
    } else if (jwk.kty === "OKP") {
      canonical = JSON.stringify({ crv: jwk.crv, kty: "OKP", x: jwk.x });
    } else {
      return nothing;
    }
    const hash = crypto.createHash("sha256").update(canonical, "utf8").digest();
    return just(Array.from(hash));
  } catch (e) {
    return nothing;
  }
};

export const exportJwkImpl = function(just, nothing, spkiDerBytes) {
  try {
    const keyObject = crypto.createPublicKey({
      key: Buffer.from(spkiDerBytes),
      format: "der",
      type: "spki"
    });
    const jwk = keyObject.export({ format: "jwk" });
    return just(JSON.stringify(jwk));
  } catch (e) {
    return nothing;
  }
};
