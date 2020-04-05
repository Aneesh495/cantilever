-- | Module: Cantilever.Core.CT.SCT
-- | Description: RFC 6962 Signed Certificate Timestamp (SCT) structures,
-- |              precertificate poisoning, and TLS binary codecs.
-- |
-- | Implements complete SCT generation, binary TLS encoding (RFC 6962 Section 3.2),
-- | precertificate poison extension stripping, X.509 embedded extension creation
-- | (OID 1.3.6.1.4.1.11129.2.4.2), and digital signature verification.

module Cantilever.Core.CT.SCT
  ( ByteArray
  , DigitallySigned
  , SignedCertificateTimestamp
  , SerializedSCTList
  , computeLogId
  , createSCT
  , serializeSCT
  , deserializeSCT
  , serializeSCTList
  , createEmbeddedSctExtension
  , removePrecertificatePoison
  , verifySCTSignature
  ) where

import Prelude

import Cantilever.Core.ASN1.DER (encodeDER)
import Cantilever.Core.ASN1.OID (OID(..))
import Cantilever.Core.ASN1.Types (ASN1(..), ASN1Value(..), TagForm(..), makeUniversalTag)
import Cantilever.Core.Crypto.BigInt (BigInt, toOctets)
import Cantilever.Core.Crypto.BigInt as BigInt
import Cantilever.Core.Crypto.Hash (sha256)
import Cantilever.Core.Crypto.Key (PrivateKey, PublicKey)
import Cantilever.Core.Crypto.Signature (SignatureAlgorithm(..), signData, verifySignature)
import Cantilever.Core.X509.Extensions (Extension, ExtensionValue(..))
import Cantilever.Core.X509.Types (Certificate)
import Data.Array (drop, filter, length, replicate, take, uncons)
import Data.Either (Either(..))
import Data.Maybe (Maybe(..), fromMaybe)

-- | Byte array alias representing octets (0..255).
type ByteArray = Array Int

-- | RFC 5246 / RFC 6962 DigitallySigned structure.
type DigitallySigned =
  { hashAlgorithm :: Int  -- 4 = SHA256
  , sigAlgorithm  :: Int  -- 1 = RSA, 3 = ECDSA
  , signature     :: ByteArray
  }

-- | RFC 6962 Section 3.2 Signed Certificate Timestamp.
type SignedCertificateTimestamp =
  { version    :: Int       -- 0 = v1
  , logId      :: ByteArray -- 32-byte SHA-256 of log SubjectPublicKeyInfo
  , timestamp  :: BigInt    -- Milliseconds since UNIX epoch
  , extensions :: ByteArray -- Typically empty
  , signature  :: DigitallySigned
  }

-- | Sequence of serialized SCTs encoded with 2-byte total length prefix.
type SerializedSCTList = ByteArray

-- | Computes 32-byte Log ID by hashing log SubjectPublicKeyInfo SPKI DER bytes.
computeLogId :: PublicKey -> ByteArray
computeLogId pubKey = sha256 pubKey.rawSpki

-- | Encodes a BigInt timestamp into exactly 8 big-endian bytes.
encodeTimestamp64 :: BigInt -> ByteArray
encodeTimestamp64 ts =
  let raw = toOctets ts
      len = length raw
  in
    if len >= 8 then take 8 (drop (len - 8) raw)
    else replicate (8 - len) 0 <> raw

-- | Constructs and signs a SignedCertificateTimestamp for a certificate/precertificate.
createSCT
  :: PrivateKey
  -> PublicKey
  -> BigInt
  -> ByteArray
  -> SignedCertificateTimestamp
createSCT logPrivKey logPubKey epochMs certEntryDer =
  let
    v = 0
    lid = computeLogId logPubKey
    tsBytes = encodeTimestamp64 epochMs
    -- RFC 6962 Section 3.2 digitally-signed payload:
    -- version(1) || signature_type(0 for cert, 1 for precert) || timestamp(8) || entry_type(0) || certEntry || extensions(2)
    signedPayload = [v, 0] <> tsBytes <> [0, 0] <> certEntryDer <> [0, 0]
    sigBytes = fromMaybe [] (signData RsaSha256 logPrivKey signedPayload)
    sigStruct =
      { hashAlgorithm: 4
      , sigAlgorithm: 1
      , signature: sigBytes
      }
  in
    { version: v
    , logId: lid
    , timestamp: epochMs
    , extensions: []
    , signature: sigStruct
    }

-- | Serializes an SCT into TLS binary format (RFC 6962 Section 3.2).
serializeSCT :: SignedCertificateTimestamp -> ByteArray
serializeSCT sct =
  let
    vByte = [sct.version]
    lidBytes = sct.logId
    tsBytes = encodeTimestamp64 sct.timestamp
    extLen = length sct.extensions
    extLenBytes = [extLen / 256, extLen `mod` 256]
    extBytes = sct.extensions

    sigHashByte = [sct.signature.hashAlgorithm]
    sigAlgByte = [sct.signature.sigAlgorithm]
    sigLen = length sct.signature.signature
    sigLenBytes = [sigLen / 256, sigLen `mod` 256]
    sigPayload = sct.signature.signature

    digitallySignedBytes = sigHashByte <> sigAlgByte <> sigLenBytes <> sigPayload
  in
    vByte <> lidBytes <> tsBytes <> extLenBytes <> extBytes <> digitallySignedBytes

-- | Deserializes a binary TLS-encoded SCT.
deserializeSCT :: ByteArray -> Either String SignedCertificateTimestamp
deserializeSCT octets =
  let total = length octets
  in
    if total < 43 then Left "SCT binary payload too short"
    else
      let
        v = fromMaybe 0 (headByte octets)
        lid = take 32 (drop 1 octets)
        tsBytes = take 8 (drop 33 octets)
        ts = BigInt.fromOctets tsBytes
        afterTs = drop 41 octets
      in
        case uncons afterTs of
          Nothing -> Left "Truncated SCT extensions length"
          Just { head: eLenH, tail: rest1 } ->
            case uncons rest1 of
              Nothing -> Left "Truncated SCT extensions length low byte"
              Just { head: eLenL, tail: rest2 } ->
                let
                  extLen = eLenH * 256 + eLenL
                  exts = take extLen rest2
                  afterExts = drop extLen rest2
                in
                  case afterExts of
                    [_, _, _, _] ->
                      Left "Missing signature bytes in SCT"
                    _ ->
                      if length afterExts < 4 then Left "Truncated SCT signature header"
                      else
                        let
                          hashAlg = fromMaybe 4 (headByte afterExts)
                          sigAlg = fromMaybe 1 (headByte (drop 1 afterExts))
                          sLenH = fromMaybe 0 (headByte (drop 2 afterExts))
                          sLenL = fromMaybe 0 (headByte (drop 3 afterExts))
                          sigLen = sLenH * 256 + sLenL
                          sigBytes = take sigLen (drop 4 afterExts)
                        in
                          Right
                            { version: v
                            , logId: lid
                            , timestamp: ts
                            , extensions: exts
                            , signature:
                                { hashAlgorithm: hashAlg
                                , sigAlgorithm: sigAlg
                                , signature: sigBytes
                                }
                            }
  where
  headByte arr = case uncons arr of
    Just { head } -> Just head
    Nothing -> Nothing

-- | Encodes a list of SCTs into TLS SerializedSCTList format.
serializeSCTList :: Array SignedCertificateTimestamp -> SerializedSCTList
serializeSCTList scts =
  let
    encodeItem sct =
      let itemBytes = serializeSCT sct
          len = length itemBytes
      in [len / 256, len `mod` 256] <> itemBytes
    itemsPayload = scts >>= encodeItem
    totalLen = length itemsPayload
  in
    [totalLen / 256, totalLen `mod` 256] <> itemsPayload

-- | Wraps a list of SCTs into an X.509 Extension (OID 1.3.6.1.4.1.11129.2.4.2).
createEmbeddedSctExtension :: Array SignedCertificateTimestamp -> Extension
createEmbeddedSctExtension scts =
  let
    serializedList = serializeSCTList scts
    -- OID id-embedded-sct: 1.3.6.1.4.1.11129.2.4.2
    oid = OID [1, 3, 6, 1, 4, 1, 11129, 2, 4, 2]
    octetStringAst = ASN1 (makeUniversalTag 4 Primitive) (ASN1OctetString serializedList)
    derBytes = encodeDER octetStringAst
  in
    { oid
    , critical: false
    , value: EmbeddedSctList derBytes
    }

-- | Strips the CT Precertificate Poison extension (OID 1.3.6.1.4.1.11129.2.4.3).
removePrecertificatePoison :: Certificate -> Certificate
removePrecertificatePoison cert =
  let
    poisonOid = OID [1, 3, 6, 1, 4, 1, 11129, 2, 4, 3]
    filteredExts = filter (\ext -> ext.oid /= poisonOid) cert.tbsCertificate.extensions
    updatedTbs = cert.tbsCertificate { extensions = filteredExts }
  in
    cert { tbsCertificate = updatedTbs }

-- | Verifies a SignedCertificateTimestamp signature against a CT log's public key.
verifySCTSignature :: PublicKey -> SignedCertificateTimestamp -> ByteArray -> Boolean
verifySCTSignature logPubKey sct certEntryDer =
  let
    v = sct.version
    tsBytes = encodeTimestamp64 sct.timestamp
    signedPayload = [v, 0] <> tsBytes <> [0, 0] <> certEntryDer <> [0, 0]
  in
    verifySignature RsaSha256 logPubKey signedPayload sct.signature.signature
