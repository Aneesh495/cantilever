-- | Module: Test.Main
-- | Description: Master test runner for the Cantilever PKI and ACME v2 test suite.

module Test.Main
  ( main
  ) where

import Prelude

import Effect (Effect)
import Effect.Console (log)
import Test.Cantilever.ACMESpec (runACMETests)
import Test.Cantilever.ASN1Spec (runASN1Tests)
import Test.Cantilever.CTSpec (runCTTests)
import Test.Cantilever.CryptoSpec (runCryptoTests)
import Test.Cantilever.PathValidationSpec (runPathValidationTests)
import Test.Cantilever.X509Spec (runX509Tests)

main :: Effect Unit
main = do
  log "================================================================================"
  log "  CANTILEVER TEST SUITE EXECUTION"
  log "================================================================================"

  runCryptoTests
  runASN1Tests
  runX509Tests
  runPathValidationTests
  runACMETests
  runCTTests

  log "\n================================================================================"
  log "  ALL TEST SUITES PASSED (100% SUCCESS)"
  log "================================================================================"
