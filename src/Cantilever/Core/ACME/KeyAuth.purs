-- | Module: Cantilever.Core.ACME.KeyAuth
-- | Description: RFC 8555 Section 8.1 Key Authorization and validation computation.
-- |
-- | Calculates client key authorizations, DNS-01 SHA-256 digest hashes,
-- | and verifies HTTP-01 and DNS-01 challenge response payloads.

module Cantilever.Core.ACME.KeyAuth
  ( computeKeyAuthorization
  , computeDnsDigest
  , verifyHttp01Payload
  , verifyDns01Payload
  ) where

import Prelude

import Cantilever.Core.ACME.JWS (base64urlEncodeBytes, stringToUtf8Bytes)
import Cantilever.Core.Crypto.Hash (sha256)
import Cantilever.Core.Crypto.Key (PublicKey, jwkThumbprintSha256)
import Data.Maybe (fromMaybe)
import Data.String.Common (trim)

-- | Computes the RFC 8555 Section 8.1 Key Authorization string:
-- | keyAuthorization = token || "." || base64url(thumbprint(accountKey))
computeKeyAuthorization :: String -> PublicKey -> String
computeKeyAuthorization token pubKey =
  let thumbprintBytes = fromMaybe [] (jwkThumbprintSha256 pubKey)
      thumbprint = base64urlEncodeBytes thumbprintBytes
  in token <> "." <> thumbprint

-- | Computes the DNS-01 TXT record value (RFC 8555 Section 8.4):
-- | base64url(SHA-256(keyAuthorization))
computeDnsDigest :: String -> PublicKey -> String
computeDnsDigest token pubKey =
  let keyAuth = computeKeyAuthorization token pubKey
      bytes = stringToUtf8Bytes keyAuth
      digest = sha256 bytes
  in base64urlEncodeBytes digest

-- | Verifies an HTTP-01 response payload against expected key authorization.
-- | Ignores trailing whitespace as per RFC 8555 Section 8.3.
verifyHttp01Payload :: String -> PublicKey -> String -> Boolean
verifyHttp01Payload token pubKey responseBody =
  let expected = computeKeyAuthorization token pubKey
  in trim responseBody == expected

-- | Verifies a DNS-01 TXT record value against expected key authorization digest.
verifyDns01Payload :: String -> PublicKey -> String -> Boolean
verifyDns01Payload token pubKey txtRecordValue =
  let expected = computeDnsDigest token pubKey
  in trim txtRecordValue == expected
