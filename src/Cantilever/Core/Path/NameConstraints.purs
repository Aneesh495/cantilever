module Cantilever.Core.Path.NameConstraints
  ( matchesDnsSubtree
  , matchesIpSubtree
  , matchesGeneralSubtree
  , checkPermittedSubtrees
  , checkExcludedSubtrees
  , verifyGeneralNamesAgainstConstraints
  ) where

import Prelude

import Cantilever.Core.X509.Extensions (GeneralName(..), GeneralSubtree(..))
import Data.Array (drop, foldl, length, take, uncons)
import Data.Either (Either(..))
import Data.Int.Bits ((.&.))
import Data.Maybe (Maybe(..))
import Data.String.CodeUnits (toCharArray)
import Data.String.Common (toLower)

-- | Checks if candidate DNS name matches a base DNS subtree pattern per RFC 5280 Section 4.2.1.10.
matchesDnsSubtree :: String -> String -> Boolean
matchesDnsSubtree candidatePattern baseConstraint =
  let
    candidate = toLower candidatePattern
    base = toLower baseConstraint
  in
    if candidate == base then
      true
    else
      let
        baseChars = toCharArray base
        candChars = toCharArray candidate
      in
        if startsWithDot baseChars then
          -- Pattern starts with '.' e.g. ".example.com"
          -- Matches "sub.example.com" and "example.com"
          let baseWithoutDot = drop 1 baseChars
          in
            if candChars == baseWithoutDot then
              true
            else
              endsWithSuffix candChars baseChars
        else
          -- Pattern does not start with '.' e.g. "example.com"
          -- Matches "example.com" and "*.example.com" (i.e. ends with ".example.com")
          let dotBase = consDot baseChars
          in
            candChars == baseChars || endsWithSuffix candChars dotBase
  where
  startsWithDot cs =
    case uncons cs of
      Just { head } -> head == '.'
      Nothing -> false

  consDot cs = [ '.' ] <> cs

  endsWithSuffix full suffix =
    let fLen = length full
        sLen = length suffix
    in if fLen <= sLen then false
       else drop (fLen - sLen) full == suffix

-- | Checks if an IP address matches an IP subnet constraint.
-- | For IPv4: base constraint is 8 bytes (4 bytes IP + 4 bytes netmask).
-- | For IPv6: base constraint is 32 bytes (16 bytes IP + 16 bytes netmask).
matchesIpSubtree :: Array Int -> Array Int -> Boolean
matchesIpSubtree candidate baseWithMask =
  let
    cLen = length candidate
    bLen = length baseWithMask
  in
    if cLen == 4 && bLen == 8 then
      let
        baseIp = take 4 baseWithMask
        mask = drop 4 baseWithMask
      in
        compareWithMask candidate baseIp mask 4
    else if cLen == 16 && bLen == 32 then
      let
        baseIp = take 16 baseWithMask
        mask = drop 16 baseWithMask
      in
        compareWithMask candidate baseIp mask 16
    else
      false
  where
  compareWithMask cand base mask n =
    foldl (\acc i ->
      acc &&
      let
        cByte = getByte cand i
        bByte = getByte base i
        mByte = getByte mask i
      in
        (cByte .&. mByte) == (bByte .&. mByte)
    ) true (makeIndices n)

  getByte arr i =
    case uncons (drop i arr) of
      Just { head } -> head
      Nothing -> 0

  makeIndices 4 = [ 0, 1, 2, 3 ]
  makeIndices 16 = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 ]
  makeIndices _ = []

-- | Checks whether a GeneralName satisfies a single GeneralSubtree constraint.
matchesGeneralSubtree :: GeneralName -> GeneralSubtree -> Boolean
matchesGeneralSubtree gn (GeneralSubtree { base }) =
  case gn, base of
    DnsName cand, DnsName baseDns ->
      matchesDnsSubtree cand baseDns
    IpAddress cand, IpAddress baseIp ->
      matchesIpSubtree cand baseIp
    Rfc822Name cand, Rfc822Name baseEmail ->
      toLower cand == toLower baseEmail
    Uri cand, Uri baseUri ->
      toLower cand == toLower baseUri
    _, _ -> false

-- | Verifies that candidate name falls within at least one permitted subtree.
-- | If permittedSubtrees is empty, all names are permitted.
checkPermittedSubtrees :: Array GeneralSubtree -> GeneralName -> Boolean
checkPermittedSubtrees permitted gn =
  if length permitted == 0 then
    true
  else
    foldl (\acc subtree -> acc || matchesGeneralSubtree gn subtree) false permitted

-- | Verifies that candidate name does NOT fall within any excluded subtree.
checkExcludedSubtrees :: Array GeneralSubtree -> GeneralName -> Boolean
checkExcludedSubtrees excluded gn =
  foldl (\acc subtree -> acc && not (matchesGeneralSubtree gn subtree)) true excluded

-- | Verifies an array of GeneralNames against accumulated permitted and excluded subtrees.
-- | Returns Left name on the first constraint violation.
verifyGeneralNamesAgainstConstraints
  :: Array GeneralSubtree
  -> Array GeneralSubtree
  -> Array GeneralName
  -> Either { name :: GeneralName, isExcluded :: Boolean } Unit
verifyGeneralNamesAgainstConstraints permitted excluded names =
  foldl (\acc gn ->
    case acc of
      Left _ -> acc
      Right _ ->
        if not (checkPermittedSubtrees permitted gn) then
          Left { name: gn, isExcluded: false }
        else if not (checkExcludedSubtrees excluded gn) then
          Left { name: gn, isExcluded: true }
        else
          Right unit
  ) (Right unit) names
