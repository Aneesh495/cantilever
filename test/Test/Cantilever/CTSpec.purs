-- | Module: Test.Cantilever.CTSpec
-- | Description: Unit tests for RFC 6962 Certificate Transparency Merkle tree and SCT.

module Test.Cantilever.CTSpec
  ( runCTTests
  ) where

import Prelude

import Cantilever.Core.CT.Merkle (computeRootHash, generateInclusionProof, leafHash, nodeHash, verifyInclusionProof)
import Cantilever.Core.CT.SCT (createSCT, deserializeSCT, serializeSCT)
import Cantilever.Core.Crypto.BigInt as BigInt
import Cantilever.Core.Crypto.Hash (sha256)
import Cantilever.Core.Crypto.Key (KeyAlgorithm(..), generateKeyPair)
import Data.Array (length, range)
import Data.Either (Either(..))
import Data.Maybe (Maybe(..))
import Effect (Effect)
import Test.Cantilever.TestRunner (assert, assertEq, runTestSuite)

runCTTests :: Effect Unit
runCTTests = runTestSuite "RFC 6962 Certificate Transparency Engine" do
  testMerkleLeafAndNodeHashing
  testMerkleRootAndInclusionProof
  testSctSerializationRoundtrip

testMerkleLeafAndNodeHashing :: Effect Unit
testMerkleLeafAndNodeHashing = do
  -- Leaf hash prepends 0x00
  let leafData = [ 0x01, 0x02, 0x03 ]
      lHash = leafHash leafData
      expectedLeafHash = sha256 ([ 0x00 ] <> leafData)
  assertEq "RFC 6962 Leaf hash prepends 0x00" expectedLeafHash lHash

  -- Node hash prepends 0x01
  let left = sha256 [ 0xAA ]
      right = sha256 [ 0xBB ]
      nHash = nodeHash left right
      expectedNodeHash = sha256 ([ 0x01 ] <> left <> right)
  assertEq "RFC 6962 Internal node hash prepends 0x01" expectedNodeHash nHash

testMerkleRootAndInclusionProof :: Effect Unit
testMerkleRootAndInclusionProof = do
  -- Empty tree root is sha256 []
  assertEq "Empty tree root hash" (sha256 []) (computeRootHash [])

  -- Tree with 8 leaves
  let leaves = map (\i -> [ i, i * 2, i * 3 ]) (range 0 7)
      tree = { leaves: leaves }
      root = computeRootHash leaves
  assertEq "Merkle root hash is 32 bytes" 32 (length root)

  -- Generate and verify inclusion proof for leaf 3
  case generateInclusionProof 3 tree of
    Nothing -> assert "Failed to generate audit path" false
    Just proof -> do
      case getLeaf 3 leaves of
        Nothing -> assert "Index out of bounds" false
        Just leaf3 -> do
          let validInclusion = verifyInclusionProof proof leaf3 root
          assert "RFC 6962 Merkle audit path inclusion proof verified" validInclusion
  where
  getLeaf idx arr =
    case arr of
      [l0, l1, l2, l3, l4, l5, l6, l7] ->
        if idx == 0 then Just l0
        else if idx == 1 then Just l1
        else if idx == 2 then Just l2
        else if idx == 3 then Just l3
        else if idx == 4 then Just l4
        else if idx == 5 then Just l5
        else if idx == 6 then Just l6
        else Just l7
      _ -> Nothing

testSctSerializationRoundtrip :: Effect Unit
testSctSerializationRoundtrip = do
  kp <- generateKeyPair RSA2048
  let timestampMs = BigInt.fromInt 1735689600
      certEntryDer = [ 0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05 ]

  let sct = createSCT kp.privateKey kp.publicKey timestampMs certEntryDer
      sctBytes = serializeSCT sct

  assert "SCT encoded bytes is non-empty" (length sctBytes > 0)
  case deserializeSCT sctBytes of
    Right parsed -> do
      assertEq "SCT version matches" sct.version parsed.version
      assertEq "SCT logId matches" sct.logId parsed.logId
    Left err -> assert ("SCT deserialize failed: " <> err) false
