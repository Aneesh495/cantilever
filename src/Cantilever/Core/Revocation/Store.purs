-- | Module: Cantilever.Core.Revocation.Store
-- | Description: In-memory certificate revocation registry, CRL generator,
-- |              and automated OCSP responder dispatcher.
-- |
-- | Maintains active revocation state indexed by serial number, issues updated CRLs,
-- | and processes incoming OCSP status requests with RFC 6960 compliant responses.

module Cantilever.Core.Revocation.Store
  ( RevocationStore
  , emptyRevocationStore
  , recordRevocation
  , lookupRevocation
  , isRevoked
  , allRevocations
  , generateCRLFromStore
  , processOCSPRequest
  ) where

import Prelude

import Cantilever.Core.ASN1.OID (OID(..))
import Cantilever.Core.Crypto.BigInt (BigInt, toString)
import Cantilever.Core.Crypto.Key (PrivateKey)
import Cantilever.Core.Crypto.Signature (SignatureAlgorithm)
import Cantilever.Core.Revocation.CRL
  ( CRLBuilderConfig
  , encodeCRLReasonExt
  , signCRL
  , buildTBSCertList
  )
import Cantilever.Core.Revocation.OCSP
  ( OCSPRequest
  , RequestItem
  , buildBasicResponse
  )
import Cantilever.Core.Revocation.Types
  ( CRLReason
  , CertificateList
  , OCSPCertStatus(..)
  , OCSPResponse(..)
  , OCSPResponseStatus(..)
  , ResponderId(..)
  , RevokedCertificateEntry
  , SingleResponse
  )
import Cantilever.Core.X509.Name (DistinguishedName)
import Cantilever.Core.X509.Types (Certificate)
import Cantilever.Core.X509.Validity (TimeValue)
import Data.Array (fromFoldable)
import Data.Map (Map)
import Data.Map as Map
import Data.Maybe (Maybe(..))

-- | In-memory revocation registry indexing revoked entries by serial string representation.
type RevocationStore =
  { entries :: Map String RevokedCertificateEntry
  }

-- | Constructs an empty revocation store.
emptyRevocationStore :: RevocationStore
emptyRevocationStore =
  { entries: Map.empty
  }

-- | Records a certificate revocation event in the store.
recordRevocation
  :: RevocationStore
  -> BigInt
  -> TimeValue
  -> CRLReason
  -> RevocationStore
recordRevocation store serial revDate reason =
  let
    key = toString serial
    reasonExt = encodeCRLReasonExt reason
    entry =
      { userCertificate: serial
      , revocationDate: revDate
      , crlEntryExtensions: [reasonExt]
      }
    newMap = Map.insert key entry store.entries
  in
    { entries: newMap }

-- | Checks if a given serial number is marked revoked.
isRevoked :: RevocationStore -> BigInt -> Boolean
isRevoked store serial =
  let key = toString serial
  in Map.member key store.entries

-- | Retrieves revocation metadata for a given serial number if revoked.
lookupRevocation :: RevocationStore -> BigInt -> Maybe RevokedCertificateEntry
lookupRevocation store serial =
  let key = toString serial
  in Map.lookup key store.entries

-- | Returns all revoked entries registered in the store.
allRevocations :: RevocationStore -> Array RevokedCertificateEntry
allRevocations store =
  fromFoldable (Map.values store.entries)

-- | Builds and signs a fresh CRL containing all revoked entries in this store.
generateCRLFromStore
  :: RevocationStore
  -> DistinguishedName
  -> TimeValue
  -> Maybe TimeValue
  -> BigInt
  -> PrivateKey
  -> SignatureAlgorithm
  -> CertificateList
generateCRLFromStore store issuer thisUp nextUp crlNum privKey sigAlg =
  let
    revokedList = allRevocations store
    cfg :: CRLBuilderConfig
    cfg =
      { issuer
      , thisUpdate: thisUp
      , nextUpdate: nextUp
      , crlNumber: crlNum
      , revokedCertificates: revokedList
      , additionalExts: []
      }
    tbs = buildTBSCertList cfg { algorithm: OID [1, 2, 840, 113549, 1, 1, 11], parameters: Nothing }
  in
    signCRL privKey tbs sigAlg

-- | Dispatches an OCSPRequest against the store and signs an OCSPResponse.
processOCSPRequest
  :: RevocationStore
  -> Certificate
  -> PrivateKey
  -> OCSPRequest
  -> TimeValue
  -> Maybe TimeValue
  -> OCSPResponse
processOCSPRequest store caCert privKey req now nextUp =
  let
    evalSingleReq :: RequestItem -> SingleResponse
    evalSingleReq item =
      let
        serial = item.reqCert.serialNumber
        status = case lookupRevocation store serial of
          Just revEntry ->
            CertStatusRevoked
              { revocationTime: revEntry.revocationDate
              , revocationReason: Nothing
              }
          Nothing ->
            CertStatusGood
      in
        { certId: item.reqCert
        , certStatus: status
        , thisUpdate: now
        , nextUpdate: nextUp
        , singleExtensions: []
        }

    singleResponses = map evalSingleReq req.requestList
    responderId = ResponderByName caCert.tbsCertificate.subject
    basicResp = buildBasicResponse privKey responderId now singleResponses [] (Just [caCert])
  in
    OCSPResponseBasic OCSPSuccessful (Just basicResp)
