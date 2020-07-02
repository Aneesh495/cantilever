-- | Module: Test.Cantilever.CryptoSpec
-- | Description: Unit tests for cryptographic primitives and algorithms.

module Test.Cantilever.CryptoSpec
  ( runCryptoTests
  ) where

import Prelude

import Cantilever.Core.Crypto.AEAD (decryptAesGcm, deriveKeyPbkdf2, encryptAesGcm)
import Cantilever.Core.Crypto.BigInt as BigInt
import Cantilever.Core.Crypto.Galois (fromInt, invGF, mulGF, polyEvalGF, toInt)
import Cantilever.Core.Crypto.Hash (DigestAlgorithm(..), digest, fromHex, hmacSha256, toHex)
import Cantilever.Core.Crypto.Key (KeyAlgorithm(..), generateKeyPair, jwkThumbprintSha256)
import Cantilever.Core.Crypto.Shamir (combineShares, splitSecret)
import Cantilever.Core.Crypto.Signature (SignatureAlgorithm(..), signData, verifySignature)
import Data.Array (length, range)
import Data.Either (Either(..))
import Data.Maybe (Maybe(..))
import Effect (Effect)
import Test.Cantilever.TestRunner (assert, assertEq, runTestSuite)

runCryptoTests :: Effect Unit
runCryptoTests = runTestSuite "Cryptographic Primitives Engine" do
  testBigIntArithmetic
  testGaloisFieldArithmetic
  testShamirSecretSharing
  testHashingAndHmac
  testAeadAndPbkdf2
  testKeyGenerationAndSignatures

testBigIntArithmetic :: Effect Unit
testBigIntArithmetic = do
  let a = BigInt.fromInt 65537
      b = BigInt.fromInt 17
      c = a * b
  assertEq "BigInt multiplication: 65537 * 17" (BigInt.fromInt 1114129) c

  let modExp = BigInt.powMod (BigInt.fromInt 3) (BigInt.fromInt 5) (BigInt.fromInt 7)
  -- 3^5 = 243; 243 mod 7 = 5
  assertEq "BigInt powMod: 3^5 mod 7 == 5" (BigInt.fromInt 5) modExp

  let hexStr = BigInt.toHexString (BigInt.fromInt 255)
  assertEq "BigInt toHexString: 255 -> ff" "ff" hexStr

testGaloisFieldArithmetic :: Effect Unit
testGaloisFieldArithmetic = do
  -- In GF(256), a * 1 == a
  let g1 = mulGF (fromInt 42) (fromInt 1)
  assertEq "GF(256) mul identity: 42 * 1 == 42" 42 (toInt g1)

  -- In GF(256), a * inv(a) == 1 for all a > 0
  let inv42 = invGF (fromInt 42)
      prod = mulGF (fromInt 42) inv42
  assertEq "GF(256) multiplicative inverse: 42 * inv(42) == 1" 1 (toInt prod)

  -- Polynomial evaluation: P(x) = 7 + 3*x + 5*x^2 at x = 2
  let coeffs = [ fromInt 7, fromInt 3, fromInt 5 ]
      eval = polyEvalGF coeffs (fromInt 2)
  assert "GF(256) polynomial evaluation produces valid element" (toInt eval >= 0 && toInt eval < 256)

testShamirSecretSharing :: Effect Unit
testShamirSecretSharing = do
  let secret = [ 0xCA, 0xFE, 0xBA, 0xBE ]
      threshold = 3
      totalShares = 5

  res <- splitSecret threshold totalShares secret
  case res of
    Left err -> assert ("Shamir split failed: " <> err) false
    Right shares -> do
      assertEq "Shamir split produces requested share count" 5 (length shares)

      -- Reconstruct with 3 shares (shares 1, 3, 4)
      let s0 = getShare 0 shares
          s2 = getShare 2 shares
          s3 = getShare 3 shares
      case combineShares [ s0, s2, s3 ] of
        Left _ ->
          assert "Shamir reconstruct failed" false
        Right rec ->
          assertEq "Shamir (3, 5) threshold reconstruction matches original secret" secret rec
  where
  getShare idx arr =
    case arr of
      [x0, x1, x2, x3, x4] ->
        if idx == 0 then x0
        else if idx == 1 then x1
        else if idx == 2 then x2
        else if idx == 3 then x3
        else x4
      _ -> { x: 1, y: [] }

testHashingAndHmac :: Effect Unit
testHashingAndHmac = do
  -- SHA-256 test vector: "" -> e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  let emptySha256Hex = toHex (digest SHA256 [])
  assertEq "SHA-256 empty input hash vector" "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" emptySha256Hex

  -- Hex roundtrip
  case fromHex emptySha256Hex of
    Just bytes -> assertEq "Hex decode roundtrip length" 32 (length bytes)
    Nothing -> assert "Hex decode should succeed" false

  -- HMAC-SHA256
  let key = [ 0x01, 0x02, 0x03, 0x04 ]
      msg = [ 0x68, 0x65, 0x6c, 0x6c, 0x6f ]
      mac = hmacSha256 key msg
  assertEq "HMAC-SHA256 output length is 32 bytes" 32 (length mac)

testAeadAndPbkdf2 :: Effect Unit
testAeadAndPbkdf2 = do
  let key = map (\i -> i `mod` 256) (range 0 31)
      iv = map (\i -> (i * 3) `mod` 256) (range 0 11)
      plaintext = [ 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x20, 0x44, 0x61, 0x74, 0x61 ]
      aad = [ 0x01, 0x02, 0x03 ]

  let encrypted = encryptAesGcm key iv plaintext aad
  assertEq "AES-256-GCM authentication tag is 16 bytes" 16 (length encrypted.tag)

  case decryptAesGcm key iv encrypted.ciphertext encrypted.tag aad of
    Just decrypted -> assertEq "AES-256-GCM roundtrip decrypted plaintext" plaintext decrypted
    Nothing -> assert "AES-256-GCM decryption failed" false

  -- PBKDF2 derivation
  let derived = deriveKeyPbkdf2 "test-passphrase" [ 0x01, 0x02, 0x03, 0x04 ] 1000 32
  assertEq "PBKDF2 derives 32-byte key" 32 (length derived)

testKeyGenerationAndSignatures :: Effect Unit
testKeyGenerationAndSignatures = do
  -- RSA 2048 key generation and signature
  rsaKp <- generateKeyPair RSA2048
  assert "RSA 2048 keypair generated" (length rsaKp.publicKey.rawSpki > 0)

  let msg = [ 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x69, 0x67 ]
  case signData RsaSha256 rsaKp.privateKey msg of
    Just sig -> do
      let valid = verifySignature RsaSha256 rsaKp.publicKey msg sig
      assert "RSA-SHA256 digital signature verified" valid
      let badValid = verifySignature RsaSha256 rsaKp.publicKey [ 0x00 ] sig
      assert "RSA-SHA256 rejects corrupted message" (not badValid)
    Nothing -> assert "RSA signing failed" false

  -- JWK Thumbprint computation
  case jwkThumbprintSha256 rsaKp.publicKey of
    Just thumb -> assertEq "RFC 7638 JWK thumbprint is 32 bytes" 32 (length thumb)
    Nothing -> assert "JWK thumbprint computation failed" false
