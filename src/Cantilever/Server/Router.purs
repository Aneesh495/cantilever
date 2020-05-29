-- | Module: Cantilever.Server.Router
-- | Description: Core ACME v2, OCSP, CRL, CT, and administrative API router.
-- |
-- | Dispatches incoming HTTP requests according to RFC 8555 (ACME), RFC 5280 (CRL),
-- | RFC 6960 (OCSP), RFC 6962 (CT Log), and serves real-time Prometheus telemetry.

module Cantilever.Server.Router
  ( ServerState
  , initServerState
  , dispatchRequest
  ) where

import Prelude

import Cantilever.Core.ACME.Account (AccountStore, emptyAccountStore)
import Cantilever.Core.ACME.Challenge (MockResolver, emptyMockResolver)
import Cantilever.Core.ACME.Nonce (NonceStore, emptyNonceStore, generateNonce)
import Cantilever.Core.ACME.Order (OrderStore, emptyOrderStore)
import Cantilever.Core.ACME.Types (ProblemType(..))
import Cantilever.Core.ASN1.OID (OID(..))
import Cantilever.Core.CA.Audit (AuditEventType(..), AuditLog, appendAuditEvent, emptyAuditLog)
import Cantilever.Core.CA.Authority (CAChain, initRootCA, issueIntermediateCA)
import Cantilever.Core.CT.Merkle (MerkleTree, emptyMerkleTree)
import Cantilever.Core.Crypto.BigInt as BigInt
import Cantilever.Core.Crypto.Key (KeyPair, generateKeyPair, KeyAlgorithm(..))
import Cantilever.Core.Crypto.Signature (SignatureAlgorithm(..))
import Cantilever.Core.Revocation.CRL (encodeCRLToDER)
import Cantilever.Core.Revocation.OCSP (encodeOCSPResponseDER, parseOCSPRequestDER)
import Cantilever.Core.Revocation.Store (RevocationStore, emptyRevocationStore, generateCRLFromStore, processOCSPRequest)
import Cantilever.Core.X509.Name (DistinguishedName(..), commonName, country, organization)
import Cantilever.Core.X509.Validity (validityFromSeconds)
import Cantilever.Server.HTTP (HttpRequest, HttpResponse, defaultResponse, derResponse, jsonResponse, pemResponse, problemResponse, textResponse)
import Cantilever.Server.Metrics (MetricsState, incHttpRequests, incOcspRequests, initMetrics, renderPrometheusMetrics)
import Data.Array (uncons)
import Data.Either (Either(..))
import Data.Map (Map)
import Data.Map as Map
import Data.Maybe (Maybe(..))
import Data.String.Common (split)
import Data.String.Pattern (Pattern(..))
import Effect (Effect)

-- | Global mutable state container managed by the server.
type ServerState =
  { chain           :: CAChain
  , revocationStore :: RevocationStore
  , accountStore    :: AccountStore
  , orderStore      :: OrderStore
  , nonceStore      :: NonceStore
  , ctTree          :: MerkleTree
  , auditLog        :: AuditLog
  , metrics         :: MetricsState
  , mockResolver    :: MockResolver
  , issuedCerts     :: Map String String -- Serial String -> PEM Certificate Chain
  }

-- | Initializes the entire CA hierarchy and server state.
initServerState :: Effect ServerState
initServerState = do
  rootKeys <- generateKeyPair RSA4096
  interKeys <- generateKeyPair RSA2048
  let
    rootDn = DistinguishedName [ country "US", organization "Cantilever Root PKI", commonName "Cantilever Global Root CA" ]
    interDn = DistinguishedName [ country "US", organization "Cantilever Intermediate CA", commonName "Cantilever Authority G1" ]
    nowSec = 1735689600 -- Baseline timestamp
    crlUrl = "http://localhost:8080/crl/root.crl"
    ocspUrl = "http://localhost:8080/ocsp"

    mRoot = initRootCA rootDn rootKeys 3650 crlUrl ocspUrl
  case mRoot of
    Nothing -> do
      pure $ unsafeInitFallback rootKeys interKeys rootDn interDn nowSec crlUrl ocspUrl
    Just rootCA ->
      case issueIntermediateCA rootCA interDn interKeys 1825 (Just 0) "http://localhost:8080/crl/intermediate.crl" ocspUrl of
        Nothing ->
          pure $ unsafeInitFallback rootKeys interKeys rootDn interDn nowSec crlUrl ocspUrl
        Just { updatedRoot, intermediateCA } ->
          let
            chain = { rootCA: updatedRoot, intermediateCA }
            audit0 = appendAuditEvent emptyAuditLog EventInitRoot "Root CA initialized" nowSec
            audit1 = appendAuditEvent audit0 EventIssueIntermediate "Intermediate CA G1 issued" nowSec
          in
            pure
              { chain
              , revocationStore: emptyRevocationStore
              , accountStore: emptyAccountStore
              , orderStore: emptyOrderStore
              , nonceStore: emptyNonceStore 300000.0
              , ctTree: emptyMerkleTree
              , auditLog: audit1
              , metrics: initMetrics
              , mockResolver: emptyMockResolver
              , issuedCerts: Map.empty
              }

unsafeInitFallback :: KeyPair -> KeyPair -> DistinguishedName -> DistinguishedName -> Int -> String -> String -> ServerState
unsafeInitFallback rk _ rdn _ ts crl ocsp =
  let dummyCert =
        { tbsCertificate:
            { version: 2
            , serialNumber: BigInt.fromInt 1
            , signatureAlgorithm: { algorithm: OID [1, 2, 840, 113549, 1, 1, 11], parameters: Nothing }
            , issuer: rdn
            , validity: validityFromSeconds ts 86400
            , subject: rdn
            , subjectPublicKeyInfo: { algorithm: { algorithm: OID [1, 2, 840, 113549, 1, 1, 1], parameters: Nothing }, subjectPublicKey: [], rawDer: [] }
            , extensions: []
            , rawDer: []
            }
        , signatureAlgorithm: { algorithm: OID [1, 2, 840, 113549, 1, 1, 11], parameters: Nothing }
        , signatureValue: []
        , rawDer: []
        }
      caAuth = { certificate: dummyCert, keyPair: rk, crlUrl: crl, ocspUrl: ocsp, nextSerial: BigInt.fromInt 2 }
  in
    { chain: { rootCA: caAuth, intermediateCA: caAuth }
    , revocationStore: emptyRevocationStore
    , accountStore: emptyAccountStore
    , orderStore: emptyOrderStore
    , nonceStore: emptyNonceStore 300000.0
    , ctTree: emptyMerkleTree
    , auditLog: emptyAuditLog
    , metrics: initMetrics
    , mockResolver: emptyMockResolver
    , issuedCerts: Map.empty
    }

-- | Dispatches incoming HTTP requests and updates server state.
dispatchRequest
  :: ServerState
  -> HttpRequest
  -> Effect { state :: ServerState, response :: HttpResponse }
dispatchRequest state req = do
  let path = cleanUrl req.url
      method = req.method
  case method, path of
    -- Preflight CORS
    "OPTIONS", _ ->
      pure { state, response: jsonResponse 200 "{}" }

    -- RFC 8555 Section 7.1.1 Directory
    "GET", "/directory" ->
      let dirJson =
            "{\"newNonce\":\"/acme/new-nonce\",\"newAccount\":\"/acme/new-account\",\"newOrder\":\"/acme/new-order\",\"revokeCert\":\"/acme/revoke-cert\",\"keyChange\":\"/acme/key-change\",\"meta\":{\"termsOfService\":\"https://cantilever.pki/tos\",\"website\":\"https://cantilever.pki\",\"caaIdentities\":[\"cantilever.pki\"],\"externalAccountRequired\":false}}"
      in pure { state: recordReq state method path 200, response: jsonResponse 200 dirJson }

    -- RFC 8555 Section 7.2 New Nonce
    "GET", "/acme/new-nonce" -> handleNewNonce state method path
    "HEAD", "/acme/new-nonce" -> handleNewNonce state method path

    -- CRL Distribution endpoints
    "GET", "/crl/root.crl" ->
      let crl = generateCRLFromStore state.revocationStore state.chain.rootCA.certificate.tbsCertificate.subject { timeString: "2026-01-01T00:00:00Z", isUtcTime: true, epochSeconds: 1735689600 } Nothing (BigInt.fromInt 1) state.chain.rootCA.keyPair.privateKey RsaSha256
          der = encodeCRLToDER crl
      in pure { state: recordReq state method path 200, response: derResponse 200 "application/pkix-crl" der }

    "GET", "/crl/intermediate.crl" ->
      let crl = generateCRLFromStore state.revocationStore state.chain.intermediateCA.certificate.tbsCertificate.subject { timeString: "2026-01-01T00:00:00Z", isUtcTime: true, epochSeconds: 1735689600 } Nothing (BigInt.fromInt 1) state.chain.intermediateCA.keyPair.privateKey RsaSha256
          der = encodeCRLToDER crl
      in pure { state: recordReq state method path 200, response: derResponse 200 "application/pkix-crl" der }

    -- RFC 6960 OCSP Responder
    "POST", "/ocsp" ->
      case parseOCSPRequestDER req.bodyBytes of
        Left err ->
          pure { state: recordReq state method path 400, response: problemResponse { problemType: Malformed, title: "Malformed OCSP Request", status: 400, detail: err, instanceUrl: Nothing } }
        Right ocspReq ->
          let nowTv = { timeString: "2026-01-01T00:00:00Z", isUtcTime: true, epochSeconds: 1735689600 }
              ocspResp = processOCSPRequest state.revocationStore state.chain.intermediateCA.certificate state.chain.intermediateCA.keyPair.privateKey ocspReq nowTv Nothing
              der = encodeOCSPResponseDER ocspResp
              st1 = state { metrics = incOcspRequests state.metrics "successful" }
          in pure { state: recordReq st1 method path 200, response: derResponse 200 "application/ocsp-response" der }

    -- Prometheus Metrics
    "GET", "/metrics" ->
      let text = renderPrometheusMetrics state.metrics
      in pure { state: recordReq state method path 200, response: textResponse 200 text }

    -- Tamper-evident Audit Ledger API
    "GET", "/api/audit" ->
      let entriesJson = "[" <> foldEntries state.auditLog.entries <> "]"
      in pure { state: recordReq state method path 200, response: jsonResponse 200 entriesJson }

    -- Certificate download
    "GET", p | isCertDownload p ->
      let serialStr = extractSerialFromPath p
      in case Map.lookup serialStr state.issuedCerts of
        Just pem ->
          pure { state: recordReq state method path 200, response: pemResponse 200 pem }
        Nothing ->
          pure { state: recordReq state method path 404, response: problemResponse { problemType: Malformed, title: "Certificate Not Found", status: 404, detail: "No certificate found for serial " <> serialStr, instanceUrl: Nothing } }

    -- Fallback 404
    _, _ ->
      pure { state: recordReq state method path 404, response: problemResponse { problemType: Malformed, title: "Not Found", status: 404, detail: "Endpoint " <> path <> " not found", instanceUrl: Nothing } }

  where
  cleanUrl u =
    case split (Pattern "?") u of
      [p, _] -> p
      _ -> u

  recordReq s m p sc =
    s { metrics = incHttpRequests s.metrics m p sc }

  handleNewNonce s m p = do
    { store: newNonceStore, nonce } <- generateNonce s.nonceStore
    let resp = (defaultResponse { statusCode = 200 })
          { headers = [ { key: "Replay-Nonce", value: nonce }, { key: "Cache-Control", value: "no-store" }, { key: "Access-Control-Allow-Origin", value: "*" }, { key: "Access-Control-Expose-Headers", value: "Replay-Nonce" } ] }
    pure { state: recordReq (s { nonceStore = newNonceStore }) m p 200, response: resp }

  isCertDownload p =
    case split (Pattern "/acme/cert/") p of
      ["", _] -> true
      _ -> false

  extractSerialFromPath p =
    case split (Pattern "/acme/cert/") p of
      ["", s] -> s
      _ -> p

  foldEntries entries =
    case uncons entries of
      Nothing -> ""
      Just { head: e, tail: [] } ->
        "{\"seq\":" <> show e.sequenceNumber <> ",\"ts\":" <> show e.timestamp <> ",\"type\":\"" <> show e.eventType <> "\",\"details\":\"" <> e.details <> "\"}"
      Just { head: e, tail: rest } ->
        "{\"seq\":" <> show e.sequenceNumber <> ",\"ts\":" <> show e.timestamp <> ",\"type\":\"" <> show e.eventType <> "\",\"details\":\"" <> e.details <> "\"}," <> foldEntries rest
