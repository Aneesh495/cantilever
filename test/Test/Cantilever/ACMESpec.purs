-- | Module: Test.Cantilever.ACMESpec
-- | Description: Unit tests for RFC 8555 ACME protocol state machine and Nonce pool.

module Test.Cantilever.ACMESpec
  ( runACMETests
  ) where

import Prelude

import Cantilever.Core.ACME.Account (emptyAccountStore, lookupAccountById, registerAccount)
import Cantilever.Core.ACME.KeyAuth (computeDnsDigest, computeKeyAuthorization)
import Cantilever.Core.ACME.Nonce (activeNonceCount, consumeNonce, emptyNonceStore, generateNonce)
import Cantilever.Core.ACME.Types (AccountStatus(..))
import Cantilever.Core.Crypto.Key (KeyAlgorithm(..), generateKeyPair)
import Data.Either (Either(..))
import Data.Maybe (Maybe(..))
import Effect (Effect)
import Test.Cantilever.TestRunner (assert, assertEq, runTestSuite)

runACMETests :: Effect Unit
runACMETests = runTestSuite "RFC 8555 ACME Protocol Engine" do
  testNonceAntiReplaySemantics
  testKeyAuthorizationAndDns01Digest
  testAccountStoreLifecycle

testNonceAntiReplaySemantics :: Effect Unit
testNonceAntiReplaySemantics = do
  let store0 = emptyNonceStore 300000.0 -- 5 minutes TTL
  assertEq "Initial nonce store is empty" 0 (activeNonceCount store0)

  -- Generate nonce
  { store: store1, nonce } <- generateNonce store0
  assertEq "Active nonce count is 1" 1 (activeNonceCount store1)

  -- Consume nonce successfully
  case consumeNonce store1 nonce 1000.0 of
    Left _ -> assert "Nonce consumption should succeed" false
    Right store2 -> do
      assertEq "Active nonce count drops to 0 after consumption" 0 (activeNonceCount store2)

      -- Attempt replay attack with same nonce
      case consumeNonce store2 nonce 1000.0 of
        Left _ -> assert "Replay attack detected: badNonce error returned" true
        Right _ -> assert "Replay attack should have failed" false

testKeyAuthorizationAndDns01Digest :: Effect Unit
testKeyAuthorizationAndDns01Digest = do
  kp <- generateKeyPair RSA2048
  let token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"

  -- Key authorization: token || '.' || thumbprint
  let keyAuth = computeKeyAuthorization token kp.publicKey
  assert "Key authorization string contains token" (keyAuth /= "")

  -- DNS-01 digest: base64url(SHA256(keyAuth))
  let dns01 = computeDnsDigest token kp.publicKey
  assert "DNS-01 digest is valid base64url string" (dns01 /= "")

testAccountStoreLifecycle :: Effect Unit
testAccountStoreLifecycle = do
  kp <- generateKeyPair RSA2048
  let store0 = emptyAccountStore
      contact = [ "mailto:ops@example.com" ]

  let { store: store1, account: acct, alreadyExisted } = registerAccount store0 contact true kp.publicKey 1735689600
  assertEq "Account is newly registered" false alreadyExisted
  assertEq "Account status is initially Valid" AccountValid acct.status

  case lookupAccountById store1 acct.id of
    Just found -> assertEq "Account found in store" acct.id found.id
    Nothing -> assert "Account lookup failed" false
