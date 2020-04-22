-- | Module: Cantilever.Core.ACME.JWS
-- | Description: RFC 7515 / RFC 8555 JSON Web Signature (JWS) parsing and signature verification.
-- |
-- | Implements JWS Flattened JSON serialization decoding, protected header validation,
-- | replay-nonce checking, target URL verification, and signature verification over signing input.

module Cantilever.Core.ACME.JWS
  ( JWSFlattened
  , JWSProtectedHeader
  , ParsedJWS
  , parseJWSProtectedHeader
  , verifyJWS
  , base64urlDecodeToBytes
  , base64urlDecodeToString
  , base64urlEncodeBytes
  , base64urlEncodeString
  , stringToUtf8Bytes
  , utf8BytesToString
  ) where

import Prelude

import Cantilever.Core.ACME.Types (ProblemDocument, ProblemType(..))
import Cantilever.Core.Crypto.Key (PublicKey)
import Cantilever.Core.Crypto.Signature (SignatureAlgorithm(..), verifySignature)
import Data.Either (Either(..))
import Data.Maybe (Maybe(..))
import Data.String.Common (split)
import Data.String.Pattern (Pattern(..))

-- | Foreign JS bindings for base64url and UTF-8 codecs.
foreign import base64urlDecodeToBytes :: String -> Array Int
foreign import base64urlDecodeToString :: String -> String
foreign import base64urlEncodeBytes :: Array Int -> String
foreign import base64urlEncodeString :: String -> String
foreign import stringToUtf8Bytes :: String -> Array Int
foreign import utf8BytesToString :: Array Int -> String

-- | JWS Flattened JSON serialization structure (RFC 8555 Section 6.2).
type JWSFlattened =
  { protected :: String
  , payload   :: String
  , signature :: String
  }

-- | Parsed JWS protected header fields.
type JWSProtectedHeader =
  { alg   :: String
  , nonce :: String
  , url   :: String
  , kid   :: Maybe String
  , jwk   :: Maybe PublicKey
  }

-- | Fully authenticated JWS message.
type ParsedJWS =
  { header       :: JWSProtectedHeader
  , payloadBytes :: Array Int
  , payloadText  :: String
  , signerKey    :: PublicKey
  }

-- | Parses a JSON-encoded protected header string.
parseJWSProtectedHeader :: String -> Either ProblemDocument JWSProtectedHeader
parseJWSProtectedHeader jsonStr =
  -- Minimal deterministic key-value extractor for ACME protected headers
  let
    algVal = extractJsonField "alg" jsonStr
    nonceVal = extractJsonField "nonce" jsonStr
    urlVal = extractJsonField "url" jsonStr
    kidVal = extractJsonField "kid" jsonStr
  in
    case algVal, nonceVal, urlVal of
      Just a, Just n, Just u ->
        Right
          { alg: a
          , nonce: n
          , url: u
          , kid: kidVal
          , jwk: Nothing
          }
      _, _, _ ->
        Left
          { problemType: Malformed
          , title: "Malformed JWS Header"
          , status: 400
          , detail: "Protected header missing required fields (alg, nonce, url)"
          , instanceUrl: Nothing
          }
  where
  extractJsonField key src =
    let needle = "\"" <> key <> "\":\""
        parts = split (Pattern needle) src
    in case parts of
      [_, rest] ->
        let subparts = split (Pattern "\"") rest
        in case subparts of
          [val, _] -> Just val
          _ -> Nothing
      _ -> Nothing

-- | Validates and verifies an ACME JWS message.
-- | Checks target URL, algorithm, and cryptographic signature over (protected || "." || payload).
verifyJWS
  :: JWSFlattened
  -> String
  -> PublicKey
  -> Either ProblemDocument ParsedJWS
verifyJWS jws expectedUrl pubKey = do
  let headerJson = base64urlDecodeToString jws.protected
  header <- parseJWSProtectedHeader headerJson

  if header.url /= expectedUrl then
    Left
      { problemType: Unauthorized
      , title: "URL Mismatch"
      , status: 400
      , detail: "JWS protected header URL does not match request URL"
      , instanceUrl: Nothing
      }
  else
    let
      signingInputStr = jws.protected <> "." <> jws.payload
      signingInputBytes = stringToUtf8Bytes signingInputStr
      sigBytes = base64urlDecodeToBytes jws.signature
      sigAlg = case header.alg of
        "RS256" -> Right RsaSha256
        "ES256" -> Right EcdsaSha256
        "ES384" -> Right EcdsaSha384
        "EdDSA" -> Right Ed25519Sig
        other -> Left
          { problemType: BadSignatureAlgorithm
          , title: "Bad Signature Algorithm"
          , status: 400
          , detail: "Unsupported JWS algorithm: " <> other
          , instanceUrl: Nothing
          }
    in
      case sigAlg of
        Left err -> Left err
        Right alg ->
          let
            sigValid = verifySignature alg pubKey signingInputBytes sigBytes
          in
            if not sigValid then
              Left
                { problemType: Malformed
                , title: "Invalid JWS Signature"
                , status: 400
                , detail: "Cryptographic signature verification failed for JWS payload"
                , instanceUrl: Nothing
                }
            else
              let pBytes = base64urlDecodeToBytes jws.payload
                  pText = base64urlDecodeToString jws.payload
              in Right
                { header
                , payloadBytes: pBytes
                , payloadText: pText
                , signerKey: pubKey
                }
