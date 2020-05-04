-- | Module: Cantilever.Core.ACME.Challenge
-- | Description: RFC 8555 Section 8 challenge execution and validation engine.
-- |
-- | Implements automated verification for HTTP-01 and DNS-01 challenges,
-- | with mockable resolver interfaces for sandboxed testing and live validation.

module Cantilever.Core.ACME.Challenge
  ( MockResolver
  , emptyMockResolver
  , addMockHttpResource
  , addMockDnsTxtRecord
  , validateHttp01Challenge
  , validateDns01Challenge
  , executeChallengeValidation
  ) where

import Prelude

import Cantilever.Core.ACME.KeyAuth (computeDnsDigest, computeKeyAuthorization, verifyDns01Payload, verifyHttp01Payload)
import Cantilever.Core.ACME.Types
  ( Challenge
  , ChallengeStatus(..)
  , ChallengeType(..)
  , Identifier
  , ProblemDocument
  , ProblemType(..)
  , identifierValue
  )
import Cantilever.Core.Crypto.Key (PublicKey)
import Data.Array (any)
import Data.Either (Either(..))
import Data.Map (Map)
import Data.Map as Map
import Data.Maybe (Maybe(..))

-- | Mock resolver environment holding simulated HTTP responses and DNS TXT records.
type MockResolver =
  { httpEndpoints :: Map String String         -- URL -> Response Body
  , dnsTxtRecords :: Map String (Array String) -- FQDN -> TXT records
  }

-- | Constructs an empty mock resolver.
emptyMockResolver :: MockResolver
emptyMockResolver =
  { httpEndpoints: Map.empty
  , dnsTxtRecords: Map.empty
  }

-- | Registers a mock HTTP response body for a given URL.
addMockHttpResource :: MockResolver -> String -> String -> MockResolver
addMockHttpResource res url body =
  res { httpEndpoints = Map.insert url body res.httpEndpoints }

-- | Registers simulated DNS TXT records for a given FQDN.
addMockDnsTxtRecord :: MockResolver -> String -> Array String -> MockResolver
addMockDnsTxtRecord res fqdn txts =
  res { dnsTxtRecords = Map.insert fqdn txts res.dnsTxtRecords }

-- | Validates an HTTP-01 challenge against the resolver.
validateHttp01Challenge
  :: MockResolver
  -> String
  -> String
  -> PublicKey
  -> Either ProblemDocument Unit
validateHttp01Challenge resolver domain token pubKey =
  let
    challengeUrl = "http://" <> domain <> "/.well-known/acme-challenge/" <> token
  in
    case Map.lookup challengeUrl resolver.httpEndpoints of
      Nothing ->
        Left
          { problemType: ConnectionError
          , title: "HTTP-01 Validation Failed"
          , status: 400
          , detail: "Could not connect to or retrieve " <> challengeUrl
          , instanceUrl: Nothing
          }
      Just body ->
        if verifyHttp01Payload token pubKey body then
          Right unit
        else
          let expected = computeKeyAuthorization token pubKey
          in
            Left
              { problemType: IncorrectResponse
              , title: "Incorrect HTTP-01 Key Authorization"
              , status: 400
              , detail: "Expected key authorization '" <> expected <> "' does not match response"
              , instanceUrl: Nothing
              }

-- | Validates a DNS-01 challenge against the resolver.
validateDns01Challenge
  :: MockResolver
  -> String
  -> String
  -> PublicKey
  -> Either ProblemDocument Unit
validateDns01Challenge resolver domain token pubKey =
  let
    dnsRecordName = "_acme-challenge." <> domain
  in
    case Map.lookup dnsRecordName resolver.dnsTxtRecords of
      Nothing ->
        Left
          { problemType: DnsError
          , title: "DNS-01 TXT Record Not Found"
          , status: 400
          , detail: "No TXT record found at " <> dnsRecordName
          , instanceUrl: Nothing
          }
      Just txtList ->
        let matches = any (verifyDns01Payload token pubKey) txtList
        in
          if matches then
            Right unit
          else
            let expected = computeDnsDigest token pubKey
            in
              Left
                { problemType: IncorrectResponse
                , title: "Incorrect DNS-01 TXT Digest"
                , status: 400
                , detail: "None of the TXT records at " <> dnsRecordName <> " matched expected digest '" <> expected <> "'"
                , instanceUrl: Nothing
                }

-- | Dispatches challenge validation based on challenge type and identifier.
executeChallengeValidation
  :: MockResolver
  -> Identifier
  -> Challenge
  -> PublicKey
  -> Int
  -> Challenge
executeChallengeValidation resolver ident chal pubKey nowEpoch =
  let
    domain = identifierValue ident
    result = case chal.challengeType of
      Http01 -> validateHttp01Challenge resolver domain chal.token pubKey
      Dns01 -> validateDns01Challenge resolver domain chal.token pubKey
      TlsAlpn01 ->
        Left
          { problemType: UnsupportedIdentifier
          , title: "Unsupported Challenge Type"
          , status: 400
          , detail: "tls-alpn-01 validation is currently unsupported"
          , instanceUrl: Nothing
          }
  in
    case result of
      Right _ ->
        chal
          { status = ChallengeValid
          , validatedAt = Just nowEpoch
          , error = Nothing
          }
      Left err ->
        chal
          { status = ChallengeInvalid
          , validatedAt = Just nowEpoch
          , error = Just err
          }
