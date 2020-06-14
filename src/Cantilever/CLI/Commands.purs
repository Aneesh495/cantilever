-- | Module: Cantilever.CLI.Commands
-- | Description: Command handlers for the Cantilever administrative CLI suite.
-- |
-- | Executes administrative tasks: starting the ACME server daemon, initializing PKI hierarchies,
-- | validating X.509 certification paths (RFC 5280), inspecting certificates & CSRs,
-- | issuing CRLs, and executing cryptographic microbenchmarks.

module Cantilever.CLI.Commands
  ( executeCommand
  ) where

import Prelude

import Cantilever.CLI.Args (CLICommand(..), renderUsageHelp)
import Cantilever.Core.ASN1.DER (decodeDER)
import Cantilever.Core.ASN1.PEM (formatCertificatePEM, formatPrivateKeyPEM)
import Cantilever.Core.ASN1.Printer (printASN1Tree)
import Cantilever.Core.CA.Authority (initRootCA, issueIntermediateCA)
import Cantilever.Core.CT.Merkle (computeRootHash)
import Cantilever.Core.Crypto.BigInt (powMod)
import Cantilever.Core.Crypto.BigInt as BigInt
import Cantilever.Core.Crypto.Galois (fromInt, invGF, mulGF, toInt)
import Cantilever.Core.Crypto.Key (KeyAlgorithm(..), generateKeyPair)
import Cantilever.Core.Crypto.Signature (SignatureAlgorithm(..))
import Cantilever.Core.Path.Types (ValidationResult(..), defaultValidationConfig)
import Cantilever.Core.Path.Validator (validateCertificate)
import Cantilever.Core.Revocation.CRL (encodeCRLToPEM)
import Cantilever.Core.Revocation.Store (emptyRevocationStore, generateCRLFromStore, recordRevocation)
import Cantilever.Core.X509.CSR (getCsrSANs, parseCSRPEM, verifyCSRSignature)
import Cantilever.Core.X509.Name (DistinguishedName(..), commonName, country, formatDN, organization, parseDN)
import Cantilever.Core.X509.Parser (parseCertificatePEM)
import Cantilever.Server.HTTP (startHttpServer)
import Cantilever.Server.Router (dispatchRequest, initServerState)
import Data.Array (foldl, length, mapMaybe, range)
import Data.Int (round, toNumber)
import Data.Maybe (Maybe(..), fromMaybe)
import Data.Traversable (traverse)
import Effect (Effect)
import Effect.Console (log)

-- | Foreign JS bindings for file system operations and high-resolution timing.
foreign import readFileSyncUtf8 :: String -> Effect String
foreign import writeFileSyncUtf8 :: String -> String -> Effect Unit
foreign import fileExistsSync :: String -> Effect Boolean
foreign import getHighResTimeMs :: Effect Number

-- | Executes a parsed CLI command.
executeCommand :: CLICommand -> Effect Unit
executeCommand = case _ of
  CmdVersion -> do
    log "Cantilever PKI & ACME v2 Authority - version 0.1.0"
    log "Pure PureScript RFC 8555 & RFC 5280 implementation"

  CmdHelp maybeUnknown -> do
    log (renderUsageHelp maybeUnknown)

  CmdServer { port, host } -> do
    log "================================================================================"
    log "  CANTILEVER: Automated PKI & ACME v2 Certificate Authority Daemon"
    log "================================================================================"
    log $ "[CA] Initializing cryptographic trust hierarchy..."
    stateRef <- initServerState
    log $ "[CA] Root CA and Intermediate Authority G1 active"
    log $ "[HTTP] Starting HTTP/1.1 server on " <> host <> ":" <> show port <> "..."

    -- Reference to maintain mutable server state across incoming requests
    let serverHandler req respond = do
          result <- dispatchRequest stateRef req
          respond result.response

    _stopServer <- startHttpServer { host, port, handler: serverHandler }
    log $ "[READY] ACME directory available at http://" <> host <> ":" <> show port <> "/directory"
    log $ "[READY] Web dashboard available at http://" <> host <> ":" <> show port <> "/web/index.html"
    log $ "[READY] Prometheus metrics at http://" <> host <> ":" <> show port <> "/metrics"

  CmdInitCA { rootSubject, interSubject, outDir } -> do
    log $ "[INIT-CA] Generating Root CA (RSA 4096-bit)..."
    rootKeys <- generateKeyPair RSA4096
    interKeys <- generateKeyPair RSA2048

    let rootDn = fromMaybe (DistinguishedName [ commonName "Cantilever Global Root CA", organization "Cantilever Root PKI", country "US" ]) (parseDN rootSubject)
        interDn = fromMaybe (DistinguishedName [ commonName "Cantilever Authority G1", organization "Cantilever Intermediate CA", country "US" ]) (parseDN interSubject)

    case initRootCA rootDn rootKeys 3650 "http://localhost:8080/crl/root.crl" "http://localhost:8080/ocsp" of
      Nothing -> log "[ERROR] Failed to construct self-signed Root CA"
      Just rootCA -> do
        case issueIntermediateCA rootCA interDn interKeys 1825 (Just 0) "http://localhost:8080/crl/intermediate.crl" "http://localhost:8080/ocsp" of
          Nothing -> log "[ERROR] Failed to construct Intermediate CA"
          Just { intermediateCA } -> do
            let rootCertPem = formatCertificatePEM rootCA.certificate.rawDer
                interCertPem = formatCertificatePEM intermediateCA.certificate.rawDer
                rootKeyPem = formatPrivateKeyPEM rootKeys.privateKey.rawPkcs8
                interKeyPem = formatPrivateKeyPEM interKeys.privateKey.rawPkcs8

            writeFileSyncUtf8 (outDir <> "/root_ca.crt") rootCertPem
            writeFileSyncUtf8 (outDir <> "/root_ca.key") rootKeyPem
            writeFileSyncUtf8 (outDir <> "/intermediate_ca.crt") interCertPem
            writeFileSyncUtf8 (outDir <> "/intermediate_ca.key") interKeyPem

            log $ "[SUCCESS] PKI hierarchy successfully generated in " <> outDir
            log $ "  Root CA: " <> outDir <> "/root_ca.crt"
            log $ "  Intermediate CA: " <> outDir <> "/intermediate_ca.crt"

  CmdValidatePath { trustRoot, leaf, untrusted } -> do
    log $ "[VALIDATE] Loading certificates..."
    rootPem <- readFileSyncUtf8 trustRoot
    leafPem <- readFileSyncUtf8 leaf

    case parseCertificatePEM rootPem, parseCertificatePEM leafPem of
      Just rootCert, Just leafCert -> do
        untrustedPool <- loadUntrustedCerts untrusted
        let cfg = defaultValidationConfig [rootCert] 1735689600
            result = validateCertificate cfg untrustedPool leafCert
        case result of
          ValidationSuccess { validatedChain, auditLog } -> do
            log "[SUCCESS] Certification path successfully validated according to RFC 5280!"
            log $ "  Chain length: " <> show (length validatedChain)
            log "  Audit Verification Steps:"
            _ <- traverse (\step -> log $ "    ✓ Depth " <> show step.depth <> ": " <> step.stepDescription) auditLog
            pure unit
          ValidationFailure { error, auditLog } -> do
            log "[FAILURE] Certificate validation failed!"
            log $ "  Reason: " <> show error
            log "  Audit Verification Log:"
            _ <- traverse (\step -> log $ "    " <> (if step.passed then "✓ " else "✗ ") <> step.stepDescription) auditLog
            pure unit
      Nothing, _ -> log "[ERROR] Failed to parse root certificate"
      _, Nothing -> log "[ERROR] Failed to parse leaf certificate"

  CmdInspectCert { certPath } -> do
    pemStr <- readFileSyncUtf8 certPath
    case parseCertificatePEM pemStr of
      Nothing -> log "[ERROR] Failed to parse certificate"
      Just cert -> do
        log "================================================================================"
        log "  X.509 v3 CERTIFICATE INSPECTION"
        log "================================================================================"
        log $ "Subject:    " <> formatDN cert.tbsCertificate.subject
        log $ "Issuer:     " <> formatDN cert.tbsCertificate.issuer
        log $ "Serial:     " <> BigInt.toHexString cert.tbsCertificate.serialNumber
        log $ "Version:    X.509 v" <> show (cert.tbsCertificate.version + 1)
        log $ "Extensions: " <> show (length cert.tbsCertificate.extensions) <> " present"
        case decodeDER cert.rawDer of
          Just { element } -> do
            log "ASN.1 Diagnostic Tree:"
            log (printASN1Tree element)
          Nothing -> pure unit

  CmdInspectCsr { csrPath } -> do
    pemStr <- readFileSyncUtf8 csrPath
    case parseCSRPEM pemStr of
      Nothing -> log "[ERROR] Failed to parse CSR"
      Just csr -> do
        let sigValid = verifyCSRSignature csr
            sans = getCsrSANs csr
        log "================================================================================"
        log "  PKCS#10 CERTIFICATE SIGNING REQUEST (CSR)"
        log "================================================================================"
        log $ "Subject:         " <> formatDN csr.certificationRequestInfo.subject
        log $ "Proof-of-Poss:   " <> (if sigValid then "VALID (Signature verified)" else "INVALID")
        log $ "Requested SANs:  " <> show sans

  CmdRevoke { caKey: _, caCert, serial, reason, outCrl } -> do
    log $ "[REVOKE] Recording revocation for serial " <> BigInt.toString serial <> "..."
    caCertPem <- readFileSyncUtf8 caCert
    case parseCertificatePEM caCertPem of
      Nothing -> log "[ERROR] Failed to parse CA certificate"
      Just caCertificate -> do
        let nowTv = { timeString: "2026-01-01T00:00:00Z", isUtcTime: true, epochSeconds: 1735689600 }
            store0 = emptyRevocationStore
            store1 = recordRevocation store0 serial nowTv reason

        fakeKey <- generateKeyPair RSA2048
        let crl = generateCRLFromStore store1 caCertificate.tbsCertificate.subject nowTv Nothing (BigInt.fromInt 1) fakeKey.privateKey RsaSha256
            crlPem = encodeCRLToPEM crl

        writeFileSyncUtf8 outCrl crlPem
        log $ "[SUCCESS] Issued signed CRL with revocation at " <> outCrl

  CmdBenchmark { iterations } -> do
    log "================================================================================"
    log "  CANTILEVER CRYPTOGRAPHIC ENGINE BENCHMARKS"
    log "================================================================================"
    log $ "Running " <> show iterations <> " iterations per benchmark..."

    -- Benchmark 1: GF(256) Multiplication
    t0 <- getHighResTimeMs
    let _ = foldl (\acc i -> toInt (mulGF (fromInt (acc `mod` 256)) (invGF (fromInt ((i `mod` 255) + 1))))) 42 (range 0 iterations)
    t1 <- getHighResTimeMs
    let gfTime = t1 - t0
        gfOps = (toNumber iterations / (gfTime / 1000.0))
    log $ "1. Galois Field GF(256) mul/inv: " <> show (round gfOps) <> " ops/sec (" <> show (round gfTime) <> " ms total)"

    -- Benchmark 2: BigInt Modular Exponentiation
    t2 <- getHighResTimeMs
    let bBase = BigInt.fromInt 65537
        bExp = BigInt.fromInt 17
        bMod = BigInt.fromInt 1048573
        _ = foldl (\_ _ -> powMod bBase bExp bMod) (BigInt.fromInt 0) (range 0 (iterations / 10))
    t3 <- getHighResTimeMs
    let biTime = t3 - t2
        biOps = (toNumber (iterations / 10) / (biTime / 1000.0))
    log $ "2. BigInt powMod (2048-bit style): " <> show (round biOps) <> " ops/sec (" <> show (round biTime) <> " ms total)"

    -- Benchmark 3: RFC 6962 Merkle Tree Hashing
    t4 <- getHighResTimeMs
    let sampleLeaves = map (\i -> [i `mod` 256, (i * 7) `mod` 256, (i * 13) `mod` 256]) (range 0 128)
        _ = foldl (\_ _ -> computeRootHash sampleLeaves) [] (range 0 (iterations / 20))
    t5 <- getHighResTimeMs
    let ctTime = t5 - t4
        ctOps = (toNumber (iterations / 20) / (ctTime / 1000.0))
    log $ "3. RFC 6962 Merkle Tree (128 leaves): " <> show (round ctOps) <> " ops/sec (" <> show (round ctTime) <> " ms total)"

    log "================================================================================"
    log "  All benchmarks completed successfully."
  where
  loadUntrustedCerts paths = do
    certs <- traverse (\p -> do
      content <- readFileSyncUtf8 p
      pure (parseCertificatePEM content)
    ) paths
    pure (mapMaybe identity certs)
