-- | Module: Cantilever.Core.CT.Merkle
-- | Description: RFC 6962 Certificate Transparency Merkle Tree, Inclusion Proofs,
-- |              and Consistency Proofs.
-- |
-- | Implements the RFC 6962 Section 2.1 tree hashing algorithm:
-- | - Leaf hash: SHA-256(0x00 || data)
-- | - Interior node hash: SHA-256(0x01 || left || right)
-- | - Largest power of 2 split (k = 2^floor(log2(N - 1)))
-- | - Inclusion proof generation and verification
-- | - Consistency proof between snapshots of size m and n

module Cantilever.Core.CT.Merkle
  ( ByteArray
  , MerkleTree
  , InclusionProof
  , ConsistencyProof
  , emptyMerkleTree
  , addLeaf
  , addLeaves
  , leafHash
  , nodeHash
  , largestPowerOf2LessThan
  , computeRootHash
  , generateInclusionProof
  , verifyInclusionProof
  , generateConsistencyProof
  , verifyConsistencyProof
  ) where

import Prelude

import Cantilever.Core.Crypto.Hash (sha256)
import Data.Array (drop, length, take, uncons)
import Data.Maybe (Maybe(..))

-- | Byte array alias representing octets (0..255).
type ByteArray = Array Int

-- | RFC 6962 Merkle Tree holding a sequence of raw leaf payloads.
type MerkleTree =
  { leaves :: Array ByteArray
  }

-- | Inclusion proof showing a leaf is in the Merkle Tree of size N at index m.
type InclusionProof =
  { leafIndex :: Int
  , treeSize  :: Int
  , auditPath :: Array ByteArray
  }

-- | Consistency proof showing a tree of size m is a valid prefix of a tree of size n.
type ConsistencyProof =
  { firstSize :: Int
  , secondSize :: Int
  , path       :: Array ByteArray
  }

-- | Constructs an empty Merkle tree.
emptyMerkleTree :: MerkleTree
emptyMerkleTree = { leaves: [] }

-- | Appends a single leaf to the tree.
addLeaf :: ByteArray -> MerkleTree -> MerkleTree
addLeaf leaf tree = { leaves: tree.leaves <> [leaf] }

-- | Appends multiple leaves to the tree.
addLeaves :: Array ByteArray -> MerkleTree -> MerkleTree
addLeaves newLeaves tree = { leaves: tree.leaves <> newLeaves }

-- | RFC 6962 Section 2.1 Leaf Hash: SHA-256(0x00 || leaf_data).
leafHash :: ByteArray -> ByteArray
leafHash octets = sha256 ([0] <> octets)

-- | RFC 6962 Section 2.1 Interior Node Hash: SHA-256(0x01 || left || right).
nodeHash :: ByteArray -> ByteArray -> ByteArray
nodeHash left right = sha256 ([1] <> left <> right)

-- | Calculates the largest power of 2 strictly less than n.
-- | For n = 7, returns 4. For n = 8, returns 4. For n = 4, returns 2.
largestPowerOf2LessThan :: Int -> Int
largestPowerOf2LessThan n =
  if n <= 1 then 0
  else loop 1
  where
  loop k =
    if k * 2 >= n then k
    else loop (k * 2)

-- | Recursively computes the Merkle Tree Head (MTH) for a slice of leaves.
computeRootHash :: Array ByteArray -> ByteArray
computeRootHash leaves =
  let n = length leaves
  in
    if n == 0 then
      sha256 []
    else if n == 1 then
      case uncons leaves of
        Just { head } -> leafHash head
        Nothing -> sha256 []
    else
      let
        k = largestPowerOf2LessThan n
        leftLeaves = take k leaves
        rightLeaves = drop k leaves
        leftRoot = computeRootHash leftLeaves
        rightRoot = computeRootHash rightLeaves
      in
        nodeHash leftRoot rightRoot

-- | Generates an RFC 6962 inclusion proof (audit path) for the leaf at index m.
generateInclusionProof :: Int -> MerkleTree -> Maybe InclusionProof
generateInclusionProof m tree =
  let n = length tree.leaves
  in
    if m < 0 || m >= n then Nothing
    else
      let path = buildPath m tree.leaves
      in Just { leafIndex: m, treeSize: n, auditPath: path }
  where
  buildPath idx leaves =
    let count = length leaves
    in
      if count <= 1 then []
      else
        let
          k = largestPowerOf2LessThan count
          leftLeaves = take k leaves
          rightLeaves = drop k leaves
        in
          if idx < k then
            buildPath idx leftLeaves <> [computeRootHash rightLeaves]
          else
            buildPath (idx - k) rightLeaves <> [computeRootHash leftLeaves]

-- | Verifies an RFC 6962 inclusion proof against the known root hash.
verifyInclusionProof :: InclusionProof -> ByteArray -> ByteArray -> Boolean
verifyInclusionProof proof leafData expectedRoot =
  let
    initialHash = leafHash leafData
    computedRoot = foldInclusion proof.leafIndex (proof.treeSize - 1) initialHash proof.auditPath
  in
    computedRoot == expectedRoot
  where
  foldInclusion _ _ current [] = current
  foldInclusion fn sn current pathElements =
    case uncons pathElements of
      Nothing -> current
      Just { head: p, tail: rest } ->
        if (fn `mod` 2 == 1) || (fn == sn) then
          let nextCurrent = nodeHash p current
              nextFn = fn / 2
              nextSn = sn / 2
          in foldInclusion nextFn nextSn nextCurrent rest
        else
          let nextCurrent = nodeHash current p
              nextFn = fn / 2
              nextSn = sn / 2
          in foldInclusion nextFn nextSn nextCurrent rest

-- | Generates an RFC 6962 consistency proof between tree snapshot of size m and tree of size n.
generateConsistencyProof :: Int -> Int -> MerkleTree -> Maybe ConsistencyProof
generateConsistencyProof m n tree =
  let total = length tree.leaves
  in
    if m <= 0 || m > n || n > total then Nothing
    else if m == n then
      Just { firstSize: m, secondSize: n, path: [] }
    else
      let leavesN = take n tree.leaves
          path = subProof m leavesN true
      in Just { firstSize: m, secondSize: n, path }
  where
  subProof mVal leaves isComplete =
    let count = length leaves
    in
      if mVal == count then
        if isComplete then []
        else [computeRootHash leaves]
      else
        let
          k = largestPowerOf2LessThan count
          leftLeaves = take k leaves
          rightLeaves = drop k leaves
        in
          if mVal <= k then
            subProof mVal leftLeaves false <> [computeRootHash rightLeaves]
          else
            subProof (mVal - k) rightLeaves isComplete <> [computeRootHash leftLeaves]

-- | Verifies an RFC 6962 consistency proof between two known tree heads (root1 and root2).
verifyConsistencyProof :: ConsistencyProof -> ByteArray -> ByteArray -> Boolean
verifyConsistencyProof proof root1 root2 =
  let
    m = proof.firstSize
    n = proof.secondSize
  in
    if m == n then
      proof.path == [] && root1 == root2
    else
      case uncons proof.path of
        Nothing -> false
        Just { head: firstElem, tail: rest } ->
          let
            fn = m - 1
            sn = n - 1
            p2 = isPowerOf2 m
            { fr, sr } =
              if p2 then
                { fr: firstElem, sr: firstElem }
              else
                { fr: firstElem, sr: firstElem }
            { finalFr, finalSr } = verifyStep fn sn fr sr rest
          in
            finalFr == root1 && finalSr == root2
  where
  isPowerOf2 v =
    if v <= 0 then false
    else if v == 1 then true
    else if v `mod` 2 /= 0 then false
    else isPowerOf2 (v / 2)

  verifyStep _ _ curFr curSr [] = { finalFr: curFr, finalSr: curSr }
  verifyStep fn sn curFr curSr pathNodes =
    case uncons pathNodes of
      Nothing -> { finalFr: curFr, finalSr: curSr }
      Just { head: p, tail: rest } ->
        if sn == 0 then { finalFr: curFr, finalSr: curSr }
        else if (fn `mod` 2 == 1) || (fn == sn) then
          let nextFr = nodeHash p curFr
              nextSr = nodeHash p curSr
          in verifyStep (fn / 2) (sn / 2) nextFr nextSr rest
        else
          let nextSr = nodeHash curSr p
          in verifyStep (fn / 2) (sn / 2) curFr nextSr rest
