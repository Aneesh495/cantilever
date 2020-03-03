module Cantilever.Core.Path.Validator
  ( validatePath
  , validateCertificate
  ) where

import Prelude

import Cantilever.Core.Crypto.Key (KeyAlgorithm(..), PublicKey)
import Cantilever.Core.Crypto.Signature (SignatureAlgorithm(..), verifySignature)
import Cantilever.Core.Path.Graph (resolvePaths)
import Cantilever.Core.Path.NameConstraints (verifyGeneralNamesAgainstConstraints)
import Cantilever.Core.Path.Types
  ( ValidationConfig
  , ValidationError(..)
  , ValidationResult(..)
  , ValidationStepLog
  )
import Cantilever.Core.X509.Extensions
  ( ExtensionValue(..)
  , GeneralSubtree
  , KeyUsageFlag(..)
  , hasKeyUsage
  , isCaExtension
  )
import Cantilever.Core.X509.Name (canonicalDNCompare)
import Cantilever.Core.X509.Types (Certificate)
import Cantilever.Core.X509.Validity (isExpiredAt, isNotYetValidAt)
import Data.Array (foldl, length, uncons, (!!))
import Data.Either (Either(..))
import Data.Maybe (Maybe(..))

-- | Validates an ordered certification path [ Root, Intermediate1, ..., Leaf ]
-- | according to RFC 5280 Section 6.
validatePath :: ValidationConfig -> Array Certificate -> ValidationResult
validatePath cfg chain =
  let n = length chain
  in
    if n < 1 then
      ValidationFailure
        { error: MalformedCertificatePath "Certification path is empty"
        , auditLog: []
        }
    else if n > cfg.maxPathLength + 1 then
      ValidationFailure
        { error: MalformedCertificatePath ("Path length " <> show n <> " exceeds maximum allowed")
        , auditLog: []
        }
    else
      case uncons chain of
        Nothing ->
          ValidationFailure
            { error: MalformedCertificatePath "Certification path is empty"
            , auditLog: []
            }
        Just { head: root } ->
          if not (isTrustAnchor root cfg.trustAnchors) then
            ValidationFailure
              { error: UntrustedRootCertificate { rootSubject: root.tbsCertificate.subject }
              , auditLog: [ { depth: 0, subject: root.tbsCertificate.subject, issuer: root.tbsCertificate.issuer, stepDescription: "Trust anchor verification", passed: false } ]
              }
          else
            let initialLogs = [ { depth: 0, subject: root.tbsCertificate.subject, issuer: root.tbsCertificate.issuer, stepDescription: "Trust anchor verified", passed: true } ]
            in processChain cfg chain 1 [] [] initialLogs
  where
  isTrustAnchor candidate anchors =
    foldl (\acc a -> acc || (a.tbsCertificate.serialNumber == candidate.tbsCertificate.serialNumber &&
                             canonicalDNCompare a.tbsCertificate.subject candidate.tbsCertificate.subject)) false anchors

processChain
  :: ValidationConfig
  -> Array Certificate
  -> Int
  -> Array GeneralSubtree
  -> Array GeneralSubtree
  -> Array ValidationStepLog
  -> ValidationResult
processChain cfg chain idx permitted excluded logs =
  let n = length chain
  in
    if idx >= n then
      ValidationSuccess
        { validatedChain: chain
        , auditLog: logs
        }
    else
      case chain !! idx, chain !! (idx - 1) of
        Just cert, Just parent ->
          let
            isLeaf = idx == n - 1
            tbs = cert.tbsCertificate
            parentTbs = parent.tbsCertificate
            stepOk =
              let
                newLogs = logs <> [ { depth: idx, subject: tbs.subject, issuer: tbs.issuer, stepDescription: "Path segment verified", passed: true } ]
                { newPermitted, newExcluded } = accumulateNameConstraints tbs.extensions permitted excluded
              in
                processChain cfg chain (idx + 1) newPermitted newExcluded newLogs
            parentPubKey :: PublicKey
            parentPubKey =
              { algorithm: RSA2048
              , rawSpki: parentTbs.subjectPublicKeyInfo.rawDer
              }
            dataBytes = tbs.rawDer
            sigBytes = cert.signatureValue
            sigValid = verifySignature RsaSha256 parentPubKey dataBytes sigBytes
          in
            -- Step 1: Verify name chaining (issuer matches parent subject)
            if not (canonicalDNCompare tbs.issuer parentTbs.subject) then
              ValidationFailure
                { error: IssuerSubjectMismatch { expected: parentTbs.subject, actual: tbs.issuer }
                , auditLog: logs <> [ { depth: idx, subject: tbs.subject, issuer: tbs.issuer, stepDescription: "Name chaining verification", passed: false } ]
                }
            -- Step 2: Verify digital signature using parent public key
            else if not sigValid then
              ValidationFailure
                { error: SignatureVerificationFailed { subject: tbs.subject, issuer: tbs.issuer }
                , auditLog: logs <> [ { depth: idx, subject: tbs.subject, issuer: tbs.issuer, stepDescription: "Signature verification", passed: false } ]
                }
            -- Step 3: Verify validity period
            else if isExpiredAt (cfg.targetTime - cfg.clockSkewSeconds) tbs.validity then
              ValidationFailure
                { error: ExpiredCertificate { serial: tbs.serialNumber, notAfter: tbs.validity.notAfter.epochSeconds, targetTime: cfg.targetTime }
                , auditLog: logs <> [ { depth: idx, subject: tbs.subject, issuer: tbs.issuer, stepDescription: "Validity check (expired)", passed: false } ]
                }
            else if isNotYetValidAt (cfg.targetTime + cfg.clockSkewSeconds) tbs.validity then
              ValidationFailure
                { error: NotYetValidCertificate { serial: tbs.serialNumber, notBefore: tbs.validity.notBefore.epochSeconds, targetTime: cfg.targetTime }
                , auditLog: logs <> [ { depth: idx, subject: tbs.subject, issuer: tbs.issuer, stepDescription: "Validity check (not yet valid)", passed: false } ]
                }
            -- Step 4: Verify intermediate constraints
            else if not isLeaf then
              if not (isCaExtension tbs.extensions) then
                ValidationFailure
                  { error: BasicConstraintsNotCA { subject: tbs.subject }
                  , auditLog: logs <> [ { depth: idx, subject: tbs.subject, issuer: tbs.issuer, stepDescription: "BasicConstraints isCA check", passed: false } ]
                  }
              else if not (hasKeyUsage KeyCertSign tbs.extensions) then
                ValidationFailure
                  { error: KeyUsageConstraintViolation { subject: tbs.subject, missingFlag: KeyCertSign }
                  , auditLog: logs <> [ { depth: idx, subject: tbs.subject, issuer: tbs.issuer, stepDescription: "KeyUsage keyCertSign check", passed: false } ]
                  }
              else
                -- Check pathLenConstraint
                case extractPathLen tbs.extensions of
                  Just limit ->
                    let remainingCerts = (n - 1) - idx
                    in
                      if remainingCerts > limit then
                        ValidationFailure
                          { error: PathLengthConstraintExceeded { subject: tbs.subject, limit: limit, depth: remainingCerts }
                          , auditLog: logs <> [ { depth: idx, subject: tbs.subject, issuer: tbs.issuer, stepDescription: "Path length constraint check", passed: false } ]
                          }
                      else
                        stepOk
                  Nothing -> stepOk
            -- Step 5: Verify leaf constraints and name constraints
            else
              -- Leaf check: verify accumulated name constraints against leaf SANs
              let
                leafSans = extractAllSans tbs.extensions
                ncResult = verifyGeneralNamesAgainstConstraints permitted excluded leafSans
              in
                case ncResult of
                  Left { name, isExcluded: true } ->
                    ValidationFailure
                      { error: NameConstraintExcludedViolation { subject: tbs.subject, san: name }
                      , auditLog: logs <> [ { depth: idx, subject: tbs.subject, issuer: tbs.issuer, stepDescription: "Name constraints excluded check", passed: false } ]
                      }
                  Left { name, isExcluded: false } ->
                    ValidationFailure
                      { error: NameConstraintPermittedViolation { subject: tbs.subject, san: name }
                      , auditLog: logs <> [ { depth: idx, subject: tbs.subject, issuer: tbs.issuer, stepDescription: "Name constraints permitted check", passed: false } ]
                      }
                  Right _ ->
                    stepOk
        _, _ ->
          ValidationFailure
            { error: MalformedCertificatePath "Index out of bounds during chain traversal"
            , auditLog: logs
            }
  where
  extractPathLen exts =
    foldl (\acc ext ->
      case acc of
        Just _ -> acc
        Nothing ->
          case ext.value of
            BasicConstraints { pathLenConstraint } -> pathLenConstraint
            _ -> Nothing
    ) Nothing exts

  accumulateNameConstraints exts curPerm curExcl =
    foldl (\acc ext ->
      case ext.value of
        NameConstraints nc ->
          { newPermitted: acc.newPermitted <> nc.permittedSubtrees
          , newExcluded: acc.newExcluded <> nc.excludedSubtrees
          }
        _ -> acc
    ) { newPermitted: curPerm, newExcluded: curExcl } exts

  extractAllSans exts =
    foldl (\acc ext ->
      case ext.value of
        SubjectAltName names -> acc <> names
        _ -> acc
    ) [] exts

-- | Validates a leaf certificate against trust anchors and an untrusted pool.
-- | Automatically resolves certification paths and tests candidate chains.
validateCertificate
  :: ValidationConfig
  -> Array Certificate
  -> Certificate
  -> ValidationResult
validateCertificate cfg untrustedPool leaf =
  let candidatePaths = resolvePaths cfg.trustAnchors untrustedPool leaf
  in
    case uncons candidatePaths of
      Nothing ->
        ValidationFailure
          { error: UntrustedRootCertificate { rootSubject: leaf.tbsCertificate.issuer }
          , auditLog: [ { depth: 0, subject: leaf.tbsCertificate.subject, issuer: leaf.tbsCertificate.issuer, stepDescription: "Path building failed: no path to trusted anchor", passed: false } ]
          }
      Just _ ->
        tryPaths candidatePaths
  where
  tryPaths paths =
    case uncons paths of
      Nothing ->
        ValidationFailure
          { error: MalformedCertificatePath "No candidate paths succeeded validation"
          , auditLog: []
          }
      Just { head: path, tail: rest } ->
        case validatePath cfg path of
          res@(ValidationSuccess _) -> res
          ValidationFailure err ->
            if length rest == 0 then
              ValidationFailure err
            else
              tryPaths rest
