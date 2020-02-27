module Cantilever.Core.Path.Graph
  ( resolvePaths
  , isSelfSigned
  , findIssuerCertificate
  ) where

import Prelude

import Cantilever.Core.X509.Name (canonicalDNCompare)
import Cantilever.Core.X509.Types (Certificate)
import Data.Array (foldl, reverse)
import Data.Maybe (Maybe(..))

-- | Checks if a certificate is self-signed (Issuer == Subject).
isSelfSigned :: Certificate -> Boolean
isSelfSigned cert =
  canonicalDNCompare cert.tbsCertificate.issuer cert.tbsCertificate.subject

-- | Searches a pool of certificates for one whose Subject matches the target Issuer.
findIssuerCertificate :: Certificate -> Array Certificate -> Maybe Certificate
findIssuerCertificate target pool =
  foldl (\acc cert ->
    case acc of
      Just _ -> acc
      Nothing ->
        if canonicalDNCompare cert.tbsCertificate.subject target.tbsCertificate.issuer then
          Just cert
        else
          Nothing
  ) Nothing pool

-- | Resolves certification paths from trust anchors down to the target certificate.
-- | Output path is ordered [ TrustAnchor, Intermediate1, ..., Leaf ].
resolvePaths
  :: Array Certificate
  -> Array Certificate
  -> Certificate
  -> Array (Array Certificate)
resolvePaths trustAnchors untrustedPool leaf =
  let
    allPool = trustAnchors <> untrustedPool
    rawChains = buildUpward [] [ leaf ] (leaf.tbsCertificate.serialNumber) allPool 10
  in
    rawChains <#> reverse
  where
  buildUpward visited currentChain currentSerial pool depthRemaining =
    if depthRemaining <= 0 then
      []
    else
      let currentCert = case currentChain of
            [ c ] -> c
            _ -> foldl (\_ c -> c) leaf currentChain
      in
        if isTrustAnchor currentCert trustAnchors then
          [ currentChain ]
        else if isSelfSigned currentCert then
          -- Reached self-signed root that is NOT in trust anchors
          []
        else
          let
            candidateParents = findMatchingParents currentCert pool
          in
            foldl (\acc parent ->
              let pSerial = parent.tbsCertificate.serialNumber
              in
                -- Loop prevention: do not revisit already visited serial numbers
                if containsSerial pSerial visited then
                  acc
                else
                  let nextVisited = visited <> [ currentSerial ]
                      nextChain = currentChain <> [ parent ]
                      subPaths = buildUpward nextVisited nextChain pSerial pool (depthRemaining - 1)
                  in
                    acc <> subPaths
            ) [] candidateParents

  isTrustAnchor cert anchors =
    foldl (\acc anchor ->
      acc || (anchor.tbsCertificate.serialNumber == cert.tbsCertificate.serialNumber &&
              canonicalDNCompare anchor.tbsCertificate.subject cert.tbsCertificate.subject)
    ) false anchors

  findMatchingParents cert pool =
    foldl (\acc candidate ->
      if canonicalDNCompare candidate.tbsCertificate.subject cert.tbsCertificate.issuer then
        acc <> [ candidate ]
      else
        acc
    ) [] pool

  containsSerial s arr =
    foldl (\acc x -> acc || x == s) false arr
