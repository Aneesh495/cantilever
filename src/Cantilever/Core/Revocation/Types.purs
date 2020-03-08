-- | Module: Cantilever.Core.Revocation.Types
-- | Description: Type definitions for Certificate Revocation Lists (CRL, RFC 5280)
-- |              and Online Certificate Status Protocol (OCSP, RFC 6960).
-- |
-- | Provides standard representations for CRL entries, signed CRLs,
-- | OCSP requests and responses, and revocation status codes.

module Cantilever.Core.Revocation.Types
  ( ByteArray
  , CRLReason(..)
  , crlReasonToInt
  , crlReasonFromInt
  , RevokedCertificateEntry
  , TBSCertList
  , CertificateList
  , OCSPCertStatus(..)
  , OCSPResponseStatus(..)
  , ocspResponseStatusToInt
  , ocspResponseStatusFromInt
  , CertID
  , ResponderId(..)
  , SingleResponse
  , ResponseData
  , BasicOCSPResponse
  , OCSPResponse(..)
  ) where

import Prelude

import Cantilever.Core.Crypto.BigInt (BigInt)
import Cantilever.Core.X509.Extensions (Extension)
import Cantilever.Core.X509.Name (DistinguishedName)
import Cantilever.Core.X509.Types (AlgorithmIdentifier, Certificate)
import Cantilever.Core.X509.Validity (TimeValue)
import Data.Maybe (Maybe(..))

-- | Byte array alias representing octets (0..255).
type ByteArray = Array Int

-- | RFC 5280 Section 5.3.1 CRLReason enumeration.
data CRLReason
  = Unspecified             -- 0
  | KeyCompromise           -- 1
  | CACompromise            -- 2
  | AffiliationChanged      -- 3
  | Superseded              -- 4
  | CessationOfOperation    -- 5
  | CertificateHold         -- 6
  | RemoveFromCRL           -- 8
  | PrivilegeWithdrawn      -- 9
  | AACompromise            -- 10

derive instance eqCRLReason :: Eq CRLReason
derive instance ordCRLReason :: Ord CRLReason

instance showCRLReason :: Show CRLReason where
  show = case _ of
    Unspecified -> "unspecified (0)"
    KeyCompromise -> "keyCompromise (1)"
    CACompromise -> "cACompromise (2)"
    AffiliationChanged -> "affiliationChanged (3)"
    Superseded -> "superseded (4)"
    CessationOfOperation -> "cessationOfOperation (5)"
    CertificateHold -> "certificateHold (6)"
    RemoveFromCRL -> "removeFromCRL (8)"
    PrivilegeWithdrawn -> "privilegeWithdrawn (9)"
    AACompromise -> "aACompromise (10)"

crlReasonToInt :: CRLReason -> Int
crlReasonToInt = case _ of
  Unspecified -> 0
  KeyCompromise -> 1
  CACompromise -> 2
  AffiliationChanged -> 3
  Superseded -> 4
  CessationOfOperation -> 5
  CertificateHold -> 6
  RemoveFromCRL -> 8
  PrivilegeWithdrawn -> 9
  AACompromise -> 10

crlReasonFromInt :: Int -> Maybe CRLReason
crlReasonFromInt = case _ of
  0 -> Just Unspecified
  1 -> Just KeyCompromise
  2 -> Just CACompromise
  3 -> Just AffiliationChanged
  4 -> Just Superseded
  5 -> Just CessationOfOperation
  6 -> Just CertificateHold
  8 -> Just RemoveFromCRL
  9 -> Just PrivilegeWithdrawn
  10 -> Just AACompromise
  _ -> Nothing

-- | An entry in a RevokedCertificates sequence.
type RevokedCertificateEntry =
  { userCertificate    :: BigInt
  , revocationDate     :: TimeValue
  , crlEntryExtensions :: Array Extension
  }

-- | TBSCertList structure according to RFC 5280 Section 5.1.
type TBSCertList =
  { version             :: Maybe Int
  , signature           :: AlgorithmIdentifier
  , issuer              :: DistinguishedName
  , thisUpdate          :: TimeValue
  , nextUpdate          :: Maybe TimeValue
  , revokedCertificates :: Array RevokedCertificateEntry
  , crlExtensions       :: Array Extension
  , rawDer              :: ByteArray
  }

-- | Complete signed CertificateList (CRL).
type CertificateList =
  { tbsCertList        :: TBSCertList
  , signatureAlgorithm :: AlgorithmIdentifier
  , signatureValue     :: ByteArray
  }

-- | RFC 6960 Section 2.2 CertStatus.
data OCSPCertStatus
  = CertStatusGood
  | CertStatusRevoked
      { revocationTime   :: TimeValue
      , revocationReason :: Maybe CRLReason
      }
  | CertStatusUnknown

derive instance eqOCSPCertStatus :: Eq OCSPCertStatus

instance showOCSPCertStatus :: Show OCSPCertStatus where
  show = case _ of
    CertStatusGood -> "good"
    CertStatusRevoked r -> "revoked(time=" <> show r.revocationTime.epochSeconds <> ")"
    CertStatusUnknown -> "unknown"

-- | RFC 6960 Section 2.3 OCSPResponseStatus.
data OCSPResponseStatus
  = OCSPSuccessful        -- 0
  | OCSPMalformedRequest  -- 1
  | OCSPInternalError     -- 2
  | OCSPTryLater          -- 3
  | OCSPSigRequired       -- 5
  | OCSPUnauthorized      -- 6

derive instance eqOCSPResponseStatus :: Eq OCSPResponseStatus

ocspResponseStatusToInt :: OCSPResponseStatus -> Int
ocspResponseStatusToInt = case _ of
  OCSPSuccessful -> 0
  OCSPMalformedRequest -> 1
  OCSPInternalError -> 2
  OCSPTryLater -> 3
  OCSPSigRequired -> 5
  OCSPUnauthorized -> 6

ocspResponseStatusFromInt :: Int -> Maybe OCSPResponseStatus
ocspResponseStatusFromInt = case _ of
  0 -> Just OCSPSuccessful
  1 -> Just OCSPMalformedRequest
  2 -> Just OCSPInternalError
  3 -> Just OCSPTryLater
  5 -> Just OCSPSigRequired
  6 -> Just OCSPUnauthorized
  _ -> Nothing

-- | Identifies a certificate being queried via OCSP.
type CertID =
  { hashAlgorithm  :: AlgorithmIdentifier
  , issuerNameHash :: ByteArray
  , issuerKeyHash  :: ByteArray
  , serialNumber   :: BigInt
  }

-- | RFC 6960 ResponderID choice.
data ResponderId
  = ResponderByName DistinguishedName
  | ResponderByKeyHash ByteArray

derive instance eqResponderId :: Eq ResponderId

-- | An individual status response inside an OCSP response.
type SingleResponse =
  { certId           :: CertID
  , certStatus       :: OCSPCertStatus
  , thisUpdate       :: TimeValue
  , nextUpdate       :: Maybe TimeValue
  , singleExtensions :: Array Extension
  }

-- | ResponseData structure signed by the OCSP responder.
type ResponseData =
  { responderId        :: ResponderId
  , producedAt         :: TimeValue
  , responses          :: Array SingleResponse
  , responseExtensions :: Array Extension
  , rawDer             :: ByteArray
  }

-- | BasicOCSPResponse containing signed response data and signature.
type BasicOCSPResponse =
  { tbsResponseData    :: ResponseData
  , signatureAlgorithm :: AlgorithmIdentifier
  , signature          :: ByteArray
  , certs              :: Maybe (Array Certificate)
  }

-- | Top-level OCSPResponse envelope.
data OCSPResponse
  = OCSPResponseBasic OCSPResponseStatus (Maybe BasicOCSPResponse)
  | OCSPResponseError OCSPResponseStatus

derive instance eqOCSPResponse :: Eq OCSPResponse
