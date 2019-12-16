module Cantilever.Core.Crypto.Signature
  ( SignatureAlgorithm(..)
  , signData
  , verifySignature
  , signatureAlgorithmName
  ) where

import Prelude

import Cantilever.Core.Crypto.Key (PrivateKey, PublicKey)
import Data.Maybe (Maybe(..))

-- | Digital signature algorithms supported for certificate signing and verification.
data SignatureAlgorithm
  = RsaSha256
  | RsaSha384
  | RsaPssSha256
  | EcdsaSha256
  | EcdsaSha384
  | Ed25519Sig

derive instance eqSignatureAlgorithm :: Eq SignatureAlgorithm
derive instance ordSignatureAlgorithm :: Ord SignatureAlgorithm

instance showSignatureAlgorithm :: Show SignatureAlgorithm where
  show = signatureAlgorithmName

signatureAlgorithmName :: SignatureAlgorithm -> String
signatureAlgorithmName = case _ of
  RsaSha256 -> "RSA-SHA256"
  RsaSha384 -> "RSA-SHA384"
  RsaPssSha256 -> "RSA-PSS-SHA256"
  EcdsaSha256 -> "ECDSA-SHA256"
  EcdsaSha384 -> "ECDSA-SHA384"
  Ed25519Sig -> "Ed25519"

foreign import signDataImpl :: (forall a. a -> Maybe a) -> (forall a. Maybe a) -> String -> Array Int -> Array Int -> Maybe (Array Int)
foreign import verifySignatureImpl :: String -> Array Int -> Array Int -> Array Int -> Boolean

-- | Signs a payload using the private key and specified signature algorithm.
signData :: SignatureAlgorithm -> PrivateKey -> Array Int -> Maybe (Array Int)
signData alg privKey dataBytes =
  signDataImpl Just Nothing (signatureAlgorithmName alg) privKey.rawPkcs8 dataBytes

-- | Verifies a digital signature against the public key and payload.
verifySignature :: SignatureAlgorithm -> PublicKey -> Array Int -> Array Int -> Boolean
verifySignature alg pubKey dataBytes sigBytes =
  verifySignatureImpl (signatureAlgorithmName alg) pubKey.rawSpki dataBytes sigBytes
