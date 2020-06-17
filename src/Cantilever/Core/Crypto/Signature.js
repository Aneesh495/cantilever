// Cantilever.Core.Crypto.Signature FFI implementation
import crypto from "node:crypto";

export const signDataImpl = function(just) {
  return function(nothing) {
    return function(signAlg) {
      return function(pkcs8DerBytes) {
        return function(dataBytes) {
          try {
            const key = crypto.createPrivateKey({
              key: Buffer.from(pkcs8DerBytes),
              format: "der",
              type: "pkcs8"
            });
            const data = Buffer.from(dataBytes);

            if (signAlg === "Ed25519") {
              const sig = crypto.sign(null, data, key);
              return just(Array.from(sig));
            }

            let hashAlg = "sha256";
            let padding = undefined;
            if (signAlg === "RSA-SHA256") {
              hashAlg = "sha256";
              padding = crypto.constants.RSA_PKCS1_PADDING;
            } else if (signAlg === "RSA-SHA384") {
              hashAlg = "sha384";
              padding = crypto.constants.RSA_PKCS1_PADDING;
            } else if (signAlg === "RSA-PSS-SHA256") {
              hashAlg = "sha256";
              padding = crypto.constants.RSA_PKCS1_PSS_PADDING;
            } else if (signAlg === "ECDSA-SHA256") {
              hashAlg = "sha256";
            } else if (signAlg === "ECDSA-SHA384") {
              hashAlg = "sha384";
            }

            const signer = crypto.createSign(hashAlg);
            signer.update(data);
            signer.end();
            const signOpts = { key: key };
            if (padding !== undefined) {
              signOpts.padding = padding;
            }
            const signature = signer.sign(signOpts);
            return just(Array.from(signature));
          } catch (e) {
            return nothing;
          }
        };
      };
    };
  };
};

export const verifySignatureImpl = function(signAlg) {
  return function(spkiDerBytes) {
    return function(dataBytes) {
      return function(sigBytes) {
        try {
          const key = crypto.createPublicKey({
            key: Buffer.from(spkiDerBytes),
            format: "der",
            type: "spki"
          });
          const data = Buffer.from(dataBytes);
          const signature = Buffer.from(sigBytes);

          if (signAlg === "Ed25519") {
            return crypto.verify(null, data, key, signature);
          }

          let hashAlg = "sha256";
          let padding = undefined;
          if (signAlg === "RSA-SHA256") {
            hashAlg = "sha256";
            padding = crypto.constants.RSA_PKCS1_PADDING;
          } else if (signAlg === "RSA-SHA384") {
            hashAlg = "sha384";
            padding = crypto.constants.RSA_PKCS1_PADDING;
          } else if (signAlg === "RSA-PSS-SHA256") {
            hashAlg = "sha256";
            padding = crypto.constants.RSA_PKCS1_PSS_PADDING;
          } else if (signAlg === "ECDSA-SHA256") {
            hashAlg = "sha256";
          } else if (signAlg === "ECDSA-SHA384") {
            hashAlg = "sha384";
          }

          const verifier = crypto.createVerify(hashAlg);
          verifier.update(data);
          verifier.end();
          const verifyOpts = { key: key };
          if (padding !== undefined) {
            verifyOpts.padding = padding;
          }
          return verifier.verify(verifyOpts, signature);
        } catch (e) {
          return false;
        }
      };
    };
  };
};
