-- | Module: Cantilever.Core.CA.Authority
-- | Description: Multi-tier Certificate Authority issuance pipeline and hierarchy manager.
-- |
-- | Manages Root CA generation, Intermediate CA delegation, and automated
-- | end-entity leaf certificate issuance from validated PKCS#10 CSRs.

module Cantilever.Core.CA.Authority
  ( CAAuthority
  , CAChain
  , IssueLeafParams
  , initRootCA
  , issueIntermediateCA
  , issueLeafCertificate
  ) where

import Prelude

import Cantilever.Core.Crypto.BigInt (BigInt)
import Cantilever.Core.Crypto.BigInt as BigInt
import Cantilever.Core.Crypto.Key (KeyPair)
import Cantilever.Core.X509.Builder
  ( buildEndEntityCertificate
  , buildIntermediateCA
  , buildSelfSignedRootCA
  )
import Cantilever.Core.X509.CSR (CertificationRequest, getCsrPublicKey, getCsrSANs)
import Cantilever.Core.X509.Name (DistinguishedName)
import Cantilever.Core.X509.Types (Certificate)
import Data.Maybe (Maybe(..))

-- | Represents an active Certificate Authority instance with its certificate, key pair, and serial counter.
type CAAuthority =
  { certificate :: Certificate
  , keyPair     :: KeyPair
  , crlUrl      :: String
  , ocspUrl     :: String
  , nextSerial  :: BigInt
  }

-- | Represents a full 2-tier or 3-tier CA hierarchy.
type CAChain =
  { rootCA         :: CAAuthority
  , intermediateCA :: CAAuthority
  }

-- | Parameters for issuing an end-entity certificate.
type IssueLeafParams =
  { csr          :: CertificationRequest
  , durationDays :: Int
  }

-- | Initializes a self-signed Root CA.
initRootCA
  :: DistinguishedName
  -> KeyPair
  -> Int
  -> String
  -> String
  -> Maybe CAAuthority
initRootCA subject keyPair durationDays crlUrl ocspUrl =
  let
    serial = BigInt.fromInt 1
  in
    case buildSelfSignedRootCA subject serial durationDays keyPair of
      Just cert ->
        Just
          { certificate: cert
          , keyPair
          , crlUrl
          , ocspUrl
          , nextSerial: BigInt.fromInt 100
          }
      Nothing -> Nothing

-- | Issues an Intermediate CA certificate signed by the Root CA.
issueIntermediateCA
  :: CAAuthority
  -> DistinguishedName
  -> KeyPair
  -> Int
  -> Maybe Int
  -> String
  -> String
  -> Maybe { updatedRoot :: CAAuthority, intermediateCA :: CAAuthority }
issueIntermediateCA rootCA subSubject subKeyPair durationDays mPathLen subCrlUrl subOcspUrl =
  let
    serial = rootCA.nextSerial
  in
    case buildIntermediateCA rootCA.certificate rootCA.keyPair.privateKey subSubject serial durationDays mPathLen subKeyPair of
      Just cert ->
        let updatedRoot = rootCA { nextSerial = rootCA.nextSerial + BigInt.fromInt 1 }
            intermediate =
              { certificate: cert
              , keyPair: subKeyPair
              , crlUrl: subCrlUrl
              , ocspUrl: subOcspUrl
              , nextSerial: BigInt.fromInt 100000
              }
        in Just { updatedRoot, intermediateCA: intermediate }
      Nothing -> Nothing

-- | Issues an end-entity (leaf) certificate signed by an Intermediate CA from a validated CSR.
issueLeafCertificate
  :: CAAuthority
  -> IssueLeafParams
  -> Maybe { updatedCA :: CAAuthority, certificate :: Certificate }
issueLeafCertificate ca params =
  let
    serial = ca.nextSerial
    subjectPubKey = getCsrPublicKey params.csr
    csrSans = getCsrSANs params.csr
    subject = params.csr.certificationRequestInfo.subject
  in
    case buildEndEntityCertificate ca.certificate ca.keyPair.privateKey subject csrSans serial params.durationDays subjectPubKey of
      Just cert ->
        let updatedCA = ca { nextSerial = ca.nextSerial + BigInt.fromInt 1 }
        in Just { updatedCA, certificate: cert }
      Nothing -> Nothing
