-- | Module: Test.Cantilever.X509Spec
-- | Description: Unit tests for X.509 Distinguished Names, Extensions, Builder, and Parser.

module Test.Cantilever.X509Spec
  ( runX509Tests
  ) where

import Prelude

import Cantilever.Core.Crypto.BigInt as BigInt
import Cantilever.Core.Crypto.Key (KeyAlgorithm(..), generateKeyPair)
import Cantilever.Core.X509.Builder (buildEndEntityCertificate, buildIntermediateCA, buildSelfSignedRootCA)
import Cantilever.Core.X509.CSR (buildCSR, getCsrSANs, verifyCSRSignature)
import Cantilever.Core.X509.Name (DistinguishedName(..), canonicalDNCompare, commonName, country, formatDN, organization, parseDN)
import Cantilever.Core.X509.Validity (isValidAt, makeValidity)
import Data.Array (length)
import Data.Maybe (Maybe(..))
import Effect (Effect)
import Test.Cantilever.TestRunner (assert, assertEq, runTestSuite)

runX509Tests :: Effect Unit
runX509Tests = runTestSuite "X.509 Certificate and PKCS#10 CSR Engine" do
  testDistinguishedNameCodec
  testValidityWindowVerification
  testCertificateBuilderAndParser
  testPkcs10CsrBuilderAndProofOfPossession

testDistinguishedNameCodec :: Effect Unit
testDistinguishedNameCodec = do
  let dn = DistinguishedName
        [ commonName "example.com"
        , organization "Cantilever PKI"
        , country "US"
        ]
      formatted = formatDN dn
  assertEq "RFC 4514 DN formatting" "CN=example.com, O=Cantilever PKI, C=US" formatted

  -- Parse DN back
  case parseDN formatted of
    Just parsed -> assert "Canonical DN comparison matches" (canonicalDNCompare dn parsed)
    Nothing -> assert "parseDN failed" false

testValidityWindowVerification :: Effect Unit
testValidityWindowVerification = do
  -- Window starting at base epoch (1735689600 / 2025-01-01) for 365 days
  let val = makeValidity 1735689600 365
  assert "Certificate is valid inside validity window" (isValidAt (1735689600 + 86400) val)
  assert "Certificate is not yet valid before window" (not (isValidAt (1735689600 - 86400) val))
  assert "Certificate is expired after window" (not (isValidAt (1735689600 + 366 * 86400) val))

testCertificateBuilderAndParser :: Effect Unit
testCertificateBuilderAndParser = do
  -- 1. Generate Root CA key pair
  rootKp <- generateKeyPair RSA2048
  let rootSubject = DistinguishedName [ commonName "Root CA", organization "PKI Test", country "US" ]
      serial = BigInt.fromInt 1
      durationDays = 3650

  case buildSelfSignedRootCA rootSubject serial durationDays rootKp of
    Nothing -> assert "Root CA build failed" false
    Just rootCert -> do
      assertEq "Root CA version is v3 (2)" 2 rootCert.tbsCertificate.version
      assert "Root CA is self-signed" (canonicalDNCompare rootCert.tbsCertificate.subject rootCert.tbsCertificate.issuer)

      -- 2. Build Intermediate CA signed by Root CA
      interKp <- generateKeyPair RSA2048
      let interSubject = DistinguishedName [ commonName "Inter CA", organization "PKI Test", country "US" ]
          interSerial = BigInt.fromInt 2
      case buildIntermediateCA rootCert rootKp.privateKey interSubject interSerial 1825 (Just 0) interKp of
        Nothing -> assert "Intermediate CA build failed" false
        Just interCert -> do
          assert "Intermediate issuer matches Root subject"
            (canonicalDNCompare interCert.tbsCertificate.issuer rootCert.tbsCertificate.subject)

          -- 3. Build End-Entity Leaf Certificate
          leafKp <- generateKeyPair RSA2048
          let leafSubject = DistinguishedName [ commonName "app.example.com", country "US" ]
              leafSerial = BigInt.fromInt 100
              sans = [ "app.example.com", "www.example.com" ]
          case buildEndEntityCertificate interCert interKp.privateKey leafSubject sans leafSerial 90 leafKp.publicKey of
            Nothing -> assert "Leaf cert build failed" false
            Just leafCert -> do
              assert "Leaf issuer matches Intermediate subject"
                (canonicalDNCompare leafCert.tbsCertificate.issuer interCert.tbsCertificate.subject)

testPkcs10CsrBuilderAndProofOfPossession :: Effect Unit
testPkcs10CsrBuilderAndProofOfPossession = do
  leafKp <- generateKeyPair RSA2048
  let subject = DistinguishedName [ commonName "api.example.com" ]
      sans = [ "api.example.com", "backup.example.com" ]

  case buildCSR subject sans leafKp of
    Nothing -> assert "CSR build failed" false
    Just csr -> do
      -- Verify Proof-of-Possession signature
      let validSig = verifyCSRSignature csr
      assert "PKCS#10 Proof-of-Possession signature verified" validSig

      -- Verify SAN extraction
      let extractedSans = getCsrSANs csr
      assertEq "CSR SAN count matches" 2 (length extractedSans)
