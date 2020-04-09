-- | Module: Cantilever.Core.ACME.Types
-- | Description: RFC 8555 ACME v2 Protocol data types, state machines, and directory schemas.
-- |
-- | Defines core data types for ACME Accounts, Orders, Authorizations, Challenges,
-- | Directory endpoints, JSON Web Signatures (JWS), and RFC 7807 Problem Documents.

module Cantilever.Core.ACME.Types
  ( Identifier(..)
  , identifierValue
  , AccountStatus(..)
  , Account
  , OrderStatus(..)
  , Order
  , AuthorizationStatus(..)
  , Authorization
  , ChallengeType(..)
  , challengeTypeName
  , ChallengeStatus(..)
  , Challenge
  , Directory
  , ProblemDocument
  , ProblemType(..)
  , problemTypeUrn
  ) where

import Prelude

import Cantilever.Core.Crypto.Key (PublicKey)
import Data.Maybe (Maybe)

-- | RFC 8555 Section 9.7.7 Identifier type (DNS name or IP address).
data Identifier
  = DnsIdentifier String
  | IpIdentifier String

derive instance eqIdentifier :: Eq Identifier
derive instance ordIdentifier :: Ord Identifier

instance showIdentifier :: Show Identifier where
  show (DnsIdentifier d) = "dns:" <> d
  show (IpIdentifier ip) = "ip:" <> ip

identifierValue :: Identifier -> String
identifierValue (DnsIdentifier d) = d
identifierValue (IpIdentifier ip) = ip

-- | RFC 8555 Section 7.1.6 Account status.
data AccountStatus
  = AccountValid
  | AccountDeactivated
  | AccountRevoked

derive instance eqAccountStatus :: Eq AccountStatus

instance showAccountStatus :: Show AccountStatus where
  show = case _ of
    AccountValid -> "valid"
    AccountDeactivated -> "deactivated"
    AccountRevoked -> "revoked"

-- | RFC 8555 Section 7.1.2 Account object.
type Account =
  { id                     :: String
  , status                 :: AccountStatus
  , contact                :: Array String
  , termsOfServiceAgreed   :: Boolean
  , ordersUrl              :: String
  , publicKey              :: PublicKey
  , createdAt              :: Int
  }

-- | RFC 8555 Section 7.1.3 Order status.
data OrderStatus
  = OrderPending
  | OrderReady
  | OrderProcessing
  | OrderValid
  | OrderInvalid

derive instance eqOrderStatus :: Eq OrderStatus

instance showOrderStatus :: Show OrderStatus where
  show = case _ of
    OrderPending -> "pending"
    OrderReady -> "ready"
    OrderProcessing -> "processing"
    OrderValid -> "valid"
    OrderInvalid -> "invalid"

-- | RFC 8555 Section 7.1.4 Authorization status.
data AuthorizationStatus
  = AuthzPending
  | AuthzValid
  | AuthzInvalid
  | AuthzDeactivated
  | AuthzExpired
  | AuthzRevoked

derive instance eqAuthorizationStatus :: Eq AuthorizationStatus

instance showAuthorizationStatus :: Show AuthorizationStatus where
  show = case _ of
    AuthzPending -> "pending"
    AuthzValid -> "valid"
    AuthzInvalid -> "invalid"
    AuthzDeactivated -> "deactivated"
    AuthzExpired -> "expired"
    AuthzRevoked -> "revoked"

-- | Supported validation challenge types (RFC 8555 Section 8).
data ChallengeType
  = Http01
  | Dns01
  | TlsAlpn01

derive instance eqChallengeType :: Eq ChallengeType

challengeTypeName :: ChallengeType -> String
challengeTypeName = case _ of
  Http01 -> "http-01"
  Dns01 -> "dns-01"
  TlsAlpn01 -> "tls-alpn-01"

-- | Challenge status states.
data ChallengeStatus
  = ChallengePending
  | ChallengeProcessing
  | ChallengeValid
  | ChallengeInvalid

derive instance eqChallengeStatus :: Eq ChallengeStatus

instance showChallengeStatus :: Show ChallengeStatus where
  show = case _ of
    ChallengePending -> "pending"
    ChallengeProcessing -> "processing"
    ChallengeValid -> "valid"
    ChallengeInvalid -> "invalid"

-- | RFC 8555 Section 8.0 Challenge object.
type Challenge =
  { challengeType :: ChallengeType
  , url           :: String
  , status        :: ChallengeStatus
  , token         :: String
  , validatedAt   :: Maybe Int
  , error         :: Maybe ProblemDocument
  }

-- | RFC 8555 Section 7.1.4 Authorization object.
type Authorization =
  { id          :: String
  , identifier  :: Identifier
  , status      :: AuthorizationStatus
  , expires     :: Maybe Int
  , challenges  :: Array Challenge
  , wildcard    :: Boolean
  }

-- | RFC 8555 Section 7.1.3 Order object.
type Order =
  { id                 :: String
  , accountId          :: String
  , status             :: OrderStatus
  , expires            :: Maybe Int
  , identifiers        :: Array Identifier
  , notBefore          :: Maybe Int
  , notAfter           :: Maybe Int
  , error              :: Maybe ProblemDocument
  , authorizationUrls  :: Array String
  , finalizeUrl        :: String
  , certificateUrl     :: Maybe String
  }

-- | RFC 8555 Section 7.1.1 Directory resource.
type Directory =
  { newNonce   :: String
  , newAccount :: String
  , newOrder   :: String
  , newAuthz   :: Maybe String
  , revokeCert :: String
  , keyChange  :: String
  , meta       ::
      { termsOfService          :: Maybe String
      , website                 :: Maybe String
      , caaIdentities           :: Array String
      , externalAccountRequired :: Boolean
      }
  }

-- | Standard ACME Problem Types (RFC 8555 Section 6.7).
data ProblemType
  = AccountDoesNotExist
  | AlreadyRevoked
  | BadCSR
  | BadNonce
  | BadPublicKey
  | BadRevocationReason
  | BadSignatureAlgorithm
  | CaaError
  | Compound
  | ConnectionError
  | DnsError
  | ExternalAccountRequired
  | IncorrectResponse
  | InvalidContact
  | Malformed
  | OrderNotReady
  | RateLimited
  | RejectedIdentifier
  | ServerInternal
  | TlsError
  | Unauthorized
  | UnsupportedContact
  | UnsupportedIdentifier
  | UserActionRequired

derive instance eqProblemType :: Eq ProblemType

problemTypeUrn :: ProblemType -> String
problemTypeUrn = case _ of
  AccountDoesNotExist -> "urn:ietf:params:acme:error:accountDoesNotExist"
  AlreadyRevoked -> "urn:ietf:params:acme:error:alreadyRevoked"
  BadCSR -> "urn:ietf:params:acme:error:badCSR"
  BadNonce -> "urn:ietf:params:acme:error:badNonce"
  BadPublicKey -> "urn:ietf:params:acme:error:badPublicKey"
  BadRevocationReason -> "urn:ietf:params:acme:error:badRevocationReason"
  BadSignatureAlgorithm -> "urn:ietf:params:acme:error:badSignatureAlgorithm"
  CaaError -> "urn:ietf:params:acme:error:caa"
  Compound -> "urn:ietf:params:acme:error:compound"
  ConnectionError -> "urn:ietf:params:acme:error:connection"
  DnsError -> "urn:ietf:params:acme:error:dns"
  ExternalAccountRequired -> "urn:ietf:params:acme:error:externalAccountRequired"
  IncorrectResponse -> "urn:ietf:params:acme:error:incorrectResponse"
  InvalidContact -> "urn:ietf:params:acme:error:invalidContact"
  Malformed -> "urn:ietf:params:acme:error:malformed"
  OrderNotReady -> "urn:ietf:params:acme:error:orderNotReady"
  RateLimited -> "urn:ietf:params:acme:error:rateLimited"
  RejectedIdentifier -> "urn:ietf:params:acme:error:rejectedIdentifier"
  ServerInternal -> "urn:ietf:params:acme:error:serverInternal"
  TlsError -> "urn:ietf:params:acme:error:tls"
  Unauthorized -> "urn:ietf:params:acme:error:unauthorized"
  UnsupportedContact -> "urn:ietf:params:acme:error:unsupportedContact"
  UnsupportedIdentifier -> "urn:ietf:params:acme:error:unsupportedIdentifier"
  UserActionRequired -> "urn:ietf:params:acme:error:userActionRequired"

-- | RFC 7807 / RFC 8555 Section 6.7 Problem Details document.
type ProblemDocument =
  { problemType :: ProblemType
  , title       :: String
  , status      :: Int
  , detail      :: String
  , instanceUrl :: Maybe String
  }
