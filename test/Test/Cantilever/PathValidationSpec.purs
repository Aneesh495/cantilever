-- | Module: Test.Cantilever.PathValidationSpec
-- | Description: Unit tests for RFC 5280 path validation and Name Constraints.

module Test.Cantilever.PathValidationSpec
  ( runPathValidationTests
  ) where

import Prelude

import Cantilever.Core.Crypto.BigInt as BigInt
import Cantilever.Core.Crypto.Key (KeyAlgorithm(..), generateKeyPair)
import Cantilever.Core.Path.NameConstraints (matchesDnsSubtree)
import Cantilever.Core.Path.Types (ValidationResult(..), defaultValidationConfig)
import Cantilever.Core.Path.Validator (validateCertificate)
import Cantilever.Core.X509.Builder (buildEndEntityCertificate, buildIntermediateCA, buildSelfSignedRootCA)
import Cantilever.Core.X509.Name (DistinguishedName(..), commonName, country, organization)
import Data.Array (length)
import Data.Maybe (Maybe(..))
import Effect (Effect)
import Test.Cantilever.TestRunner (assert, assertEq, runTestSuite)

runPathValidationTests :: Effect Unit
runPathValidationTests = runTestSuite "RFC 5280 Path Validation Engine" do
  testNameConstraintSubtreeMatching
  testEndToEndCertificationPathValidation

testNameConstraintSubtreeMatching :: Effect Unit
testNameConstraintSubtreeMatching = do
  -- Permitted base subtree: .example.com
  let baseSubtree = ".example.com"
      cand1 = "api.example.com"
      cand2 = "rogue.other.com"

  assert "Permitted subtree matches valid subdomain" (matchesDnsSubtree cand1 baseSubtree)
  assert "Permitted subtree rejects foreign domain" (not (matchesDnsSubtree cand2 baseSubtree))

  -- Exact match
  assert "Permitted subtree matches exact domain" (matchesDnsSubtree "example.com" "example.com")

testEndToEndCertificationPathValidation :: Effect Unit
testEndToEndCertificationPathValidation = do
  -- 1. Build Root CA
  rootKp <- generateKeyPair RSA2048
  let rootSubject = DistinguishedName [ commonName "Validation Root CA", organization "PKI Test", country "US" ]
  case buildSelfSignedRootCA rootSubject (BigInt.fromInt 1) 3650 rootKp of
    Nothing -> assert "Root build failed" false
    Just rootCert -> do
      -- 2. Build Intermediate CA
      interKp <- generateKeyPair RSA2048
      let interSubject = DistinguishedName [ commonName "Validation Inter CA", organization "PKI Test", country "US" ]
      case buildIntermediateCA rootCert rootKp.privateKey interSubject (BigInt.fromInt 2) 1825 (Just 1) interKp of
        Nothing -> assert "Inter build failed" false
        Just interCert -> do
          -- 3. Build Leaf Certificate
          leafKp <- generateKeyPair RSA2048
          let leafSubject = DistinguishedName [ commonName "node.example.com", country "US" ]
              sans = [ "node.example.com" ]
          case buildEndEntityCertificate interCert interKp.privateKey leafSubject sans (BigInt.fromInt 100) 90 leafKp.publicKey of
            Nothing -> assert "Leaf build failed" false
            Just leafCert -> do
              -- Validate Complete 3-tier Path: Root -> Intermediate -> Leaf
              let cfg = defaultValidationConfig [ rootCert ] 1735689600
                  untrustedPool = [ interCert ]
                  result = validateCertificate cfg untrustedPool leafCert

              case result of
                ValidationSuccess { validatedChain, auditLog } -> do
                  assertEq "Validated chain has 3 certificates" 3 (length validatedChain)
                  assert "Audit log recorded steps" (length auditLog >= 2)
                ValidationFailure { error } -> do
                  assert ("Path validation failed: " <> show error) false
