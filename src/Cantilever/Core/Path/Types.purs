module Cantilever.Core.Path.Types
  ( ValidationConfig
  , ValidationError(..)
  , ValidationStepLog
  , ValidationResult(..)
  , defaultValidationConfig
  , isValidationSuccess
  , formatValidationError
  ) where

import Prelude

import Cantilever.Core.Crypto.BigInt (BigInt, toHexString)
import Cantilever.Core.X509.Extensions (GeneralName, KeyUsageFlag)
import Cantilever.Core.X509.Name (DistinguishedName, formatDN)
import Cantilever.Core.X509.Types (Certificate)

-- | Configuration parameters controlling the RFC 5280 validation algorithm.
type ValidationConfig =
  { trustAnchors :: Array Certificate
  , targetTime :: Int
  , clockSkewSeconds :: Int
  , maxPathLength :: Int
  , checkRevocation :: Boolean
  }

-- | Default validation configuration with 10-minute clock skew tolerance.
defaultValidationConfig :: Array Certificate -> Int -> ValidationConfig
defaultValidationConfig anchors time =
  { trustAnchors: anchors
  , targetTime: time
  , clockSkewSeconds: 600 -- 10 minutes clock skew tolerance
  , maxPathLength: 5
  , checkRevocation: true
  }

-- | Specific validation failures defined in RFC 5280 Section 6.
data ValidationError
  = ExpiredCertificate { serial :: BigInt, notAfter :: Int, targetTime :: Int }
  | NotYetValidCertificate { serial :: BigInt, notBefore :: Int, targetTime :: Int }
  | UntrustedRootCertificate { rootSubject :: DistinguishedName }
  | SignatureVerificationFailed { subject :: DistinguishedName, issuer :: DistinguishedName }
  | BasicConstraintsNotCA { subject :: DistinguishedName }
  | PathLengthConstraintExceeded { subject :: DistinguishedName, limit :: Int, depth :: Int }
  | KeyUsageConstraintViolation { subject :: DistinguishedName, missingFlag :: KeyUsageFlag }
  | NameConstraintPermittedViolation { subject :: DistinguishedName, san :: GeneralName }
  | NameConstraintExcludedViolation { subject :: DistinguishedName, san :: GeneralName }
  | RevokedCertificateError { serial :: BigInt, reasonCode :: Int, revocationDate :: Int }
  | CircularChainDetected { serial :: BigInt }
  | IssuerSubjectMismatch { expected :: DistinguishedName, actual :: DistinguishedName }
  | MalformedCertificatePath String

derive instance eqValidationError :: Eq ValidationError

instance showValidationError :: Show ValidationError where
  show = formatValidationError

-- | Formats a validation error into a detailed diagnostic string.
formatValidationError :: ValidationError -> String
formatValidationError = case _ of
  ExpiredCertificate r ->
    "Certificate (serial 0x" <> toHexString r.serial <> ") expired at " <>
    show r.notAfter <> " (target time is " <> show r.targetTime <> ")"
  NotYetValidCertificate r ->
    "Certificate (serial 0x" <> toHexString r.serial <> ") not yet valid until " <>
    show r.notBefore <> " (target time is " <> show r.targetTime <> ")"
  UntrustedRootCertificate r ->
    "Root CA certificate (" <> formatDN r.rootSubject <> ") is not present in trust anchors"
  SignatureVerificationFailed r ->
    "Digital signature verification failed for " <> formatDN r.subject <>
    " signed by " <> formatDN r.issuer
  BasicConstraintsNotCA r ->
    "Intermediate certificate " <> formatDN r.subject <> " is not designated as a CA"
  PathLengthConstraintExceeded r ->
    "Path length constraint exceeded at " <> formatDN r.subject <>
    ": limit is " <> show r.limit <> " but chain depth is " <> show r.depth
  KeyUsageConstraintViolation r ->
    "Certificate " <> formatDN r.subject <> " lacks required KeyUsage flag: " <> show r.missingFlag
  NameConstraintPermittedViolation r ->
    "SAN " <> show r.san <> " in certificate " <> formatDN r.subject <>
    " does not fall within permitted subtrees"
  NameConstraintExcludedViolation r ->
    "SAN " <> show r.san <> " in certificate " <> formatDN r.subject <>
    " falls within an excluded subtree"
  RevokedCertificateError r ->
    "Certificate (serial 0x" <> toHexString r.serial <> ") is revoked (reason code " <>
    show r.reasonCode <> " at " <> show r.revocationDate <> ")"
  CircularChainDetected r ->
    "Circular chain loop detected for certificate serial 0x" <> toHexString r.serial
  IssuerSubjectMismatch r ->
    "Issuer name mismatch: expected parent subject " <> formatDN r.expected <>
    " but certificate specifies " <> formatDN r.actual
  MalformedCertificatePath msg ->
    "Malformed certificate path: " <> msg

-- | Single step audit log record for diagnostics.
type ValidationStepLog =
  { depth :: Int
  , subject :: DistinguishedName
  , issuer :: DistinguishedName
  , stepDescription :: String
  , passed :: Boolean
  }

-- | Outcome of path validation.
data ValidationResult
  = ValidationSuccess
      { validatedChain :: Array Certificate
      , auditLog :: Array ValidationStepLog
      }
  | ValidationFailure
      { error :: ValidationError
      , auditLog :: Array ValidationStepLog
      }

isValidationSuccess :: ValidationResult -> Boolean
isValidationSuccess = case _ of
  ValidationSuccess _ -> true
  ValidationFailure _ -> false
