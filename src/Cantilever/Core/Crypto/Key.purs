module Cantilever.Core.Crypto.Key
  ( KeyAlgorithm(..)
  , PublicKey
  , PrivateKey
  , KeyPair
  , generateKeyPair
  , jwkThumbprintSha256
  , exportJwk
  , algorithmName
  ) where

import Prelude

import Data.Maybe (Maybe(..))
import Effect (Effect)

-- | Supported public key cryptographic algorithms.
data KeyAlgorithm
  = RSA2048
  | RSA4096
  | ECDSA_P256
  | ECDSA_P384
  | Ed25519

derive instance eqKeyAlgorithm :: Eq KeyAlgorithm
derive instance ordKeyAlgorithm :: Ord KeyAlgorithm

instance showKeyAlgorithm :: Show KeyAlgorithm where
  show = algorithmName

algorithmName :: KeyAlgorithm -> String
algorithmName = case _ of
  RSA2048 -> "RSA-2048"
  RSA4096 -> "RSA-4096"
  ECDSA_P256 -> "ECDSA-P256"
  ECDSA_P384 -> "ECDSA-P384"
  Ed25519 -> "Ed25519"

-- | Raw DER-encoded SubjectPublicKeyInfo (SPKI).
type PublicKey =
  { algorithm :: KeyAlgorithm
  , rawSpki :: Array Int
  }

-- | Raw DER-encoded PKCS#8 private key.
type PrivateKey =
  { algorithm :: KeyAlgorithm
  , rawPkcs8 :: Array Int
  }

-- | Paired public and private keys.
type KeyPair =
  { publicKey :: PublicKey
  , privateKey :: PrivateKey
  }

foreign import generateRsaKeyPairImpl :: Int -> Effect { publicKeyDer :: Array Int, privateKeyDer :: Array Int }
foreign import generateEcKeyPairImpl :: String -> Effect { publicKeyDer :: Array Int, privateKeyDer :: Array Int }
foreign import generateEd25519KeyPairImpl :: Effect { publicKeyDer :: Array Int, privateKeyDer :: Array Int }
foreign import jwkThumbprintSha256Impl :: (forall a. a -> Maybe a) -> (forall a. Maybe a) -> Array Int -> Maybe (Array Int)
foreign import exportJwkImpl :: (forall a. a -> Maybe a) -> (forall a. Maybe a) -> Array Int -> Maybe String

-- | Generates a new cryptographic key pair for the specified algorithm.
generateKeyPair :: KeyAlgorithm -> Effect KeyPair
generateKeyPair alg = do
  res <- case alg of
    RSA2048 -> generateRsaKeyPairImpl 2048
    RSA4096 -> generateRsaKeyPairImpl 4096
    ECDSA_P256 -> generateEcKeyPairImpl "prime256v1"
    ECDSA_P384 -> generateEcKeyPairImpl "secp384r1"
    Ed25519 -> generateEd25519KeyPairImpl
  pure
    { publicKey: { algorithm: alg, rawSpki: res.publicKeyDer }
    , privateKey: { algorithm: alg, rawPkcs8: res.privateKeyDer }
    }

-- | Computes the SHA-256 JWK thumbprint according to RFC 7638.
jwkThumbprintSha256 :: PublicKey -> Maybe (Array Int)
jwkThumbprintSha256 pk = jwkThumbprintSha256Impl Just Nothing pk.rawSpki

-- | Exports public key as a JSON Web Key (JWK) string.
exportJwk :: PublicKey -> Maybe String
exportJwk pk = exportJwkImpl Just Nothing pk.rawSpki
