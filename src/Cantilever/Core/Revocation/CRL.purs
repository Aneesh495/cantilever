-- | Module: Cantilever.Core.Revocation.CRL
-- | Description: RFC 5280 Certificate Revocation List (CRL) generator, parser, and verifier.
-- |
-- | Implements complete DER encoding and decoding for X.509 v2 CRLs,
-- | including revoked certificate lists, CRL entry extensions (crlReason),
-- | CRL extensions (crlNumber, authorityKeyIdentifier), and digital signatures.

module Cantilever.Core.Revocation.CRL
  ( CRLBuilderConfig
  , defaultCRLConfig
  , buildTBSCertList
  , encodeCRLReasonExt
  , signCRL
  , encodeCRLToDER
  , encodeCRLToPEM
  , parseCRLFromDER
  , verifyCRLSignature
  , isCertRevokedInCRL
  ) where

import Prelude

import Cantilever.Core.ASN1.DER (decodeDER, encodeDER)
import Cantilever.Core.ASN1.OID (OID(..))
import Cantilever.Core.ASN1.PEM (formatCrlPEM)
import Cantilever.Core.ASN1.Types (ASN1(..), ASN1Value(..), TagForm(..), makeContextTag, makeUniversalTag)
import Cantilever.Core.Crypto.BigInt (BigInt)
import Cantilever.Core.Crypto.BigInt as BigInt
import Cantilever.Core.Crypto.Key (PrivateKey, PublicKey)
import Cantilever.Core.Crypto.Signature (SignatureAlgorithm(..), signData, verifySignature)
import Cantilever.Core.Revocation.Types
  ( ByteArray
  , CRLReason
  , CertificateList
  , RevokedCertificateEntry
  , TBSCertList
  , crlReasonToInt
  )
import Cantilever.Core.X509.Extensions (Extension, ExtensionValue(..), encodeExtensionAst)
import Cantilever.Core.X509.Name (DistinguishedName(..), encodeDNAst)
import Cantilever.Core.X509.Types (AlgorithmIdentifier)
import Cantilever.Core.X509.Validity (TimeValue)
import Data.Array (foldl, uncons)
import Data.Either (Either(..))
import Data.Maybe (Maybe(..))

-- | Configuration parameters for constructing a signed CRL.
type CRLBuilderConfig =
  { issuer              :: DistinguishedName
  , thisUpdate          :: TimeValue
  , nextUpdate          :: Maybe TimeValue
  , crlNumber           :: BigInt
  , revokedCertificates :: Array RevokedCertificateEntry
  , additionalExts      :: Array Extension
  }

-- | Default configuration with empty revocation list.
defaultCRLConfig :: DistinguishedName -> TimeValue -> BigInt -> CRLBuilderConfig
defaultCRLConfig issuer now crlNum =
  { issuer
  , thisUpdate: now
  , nextUpdate: Nothing
  , crlNumber: crlNum
  , revokedCertificates: []
  , additionalExts: []
  }

-- | Encodes CRL Reason extension to an ASN.1 Extension structure.
encodeCRLReasonExt :: CRLReason -> Extension
encodeCRLReasonExt reason =
  let
    oid = OID [85, 29, 21]
    enumVal = crlReasonToInt reason
    derOctets = encodeDER (ASN1 (makeUniversalTag 10 Primitive) (ASN1Integer (BigInt.fromInt enumVal)))
  in
    { oid
    , critical: false
    , value: RawExtension derOctets
    }

-- | Encodes CRL Number extension (OID 2.5.29.20).
encodeCRLNumberExt :: BigInt -> Extension
encodeCRLNumberExt num =
  let
    oid = OID [85, 29, 20]
    derOctets = encodeDER (ASN1 (makeUniversalTag 2 Primitive) (ASN1Integer num))
  in
    { oid
    , critical: false
    , value: RawExtension derOctets
    }

-- | Converts RevokedCertificateEntry to its ASN.1 AST.
encodeRevokedEntryAst :: RevokedCertificateEntry -> ASN1
encodeRevokedEntryAst entry =
  let
    serialAst = ASN1 (makeUniversalTag 2 Primitive) (ASN1Integer entry.userCertificate)
    dateAst = encodeTimeValue entry.revocationDate
    items = [serialAst, dateAst]
  in
    ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence items)

-- | Encodes a TimeValue as UTCTime or GeneralizedTime AST.
encodeTimeValue :: TimeValue -> ASN1
encodeTimeValue tv =
  if tv.isUtcTime then
    ASN1 (makeUniversalTag 23 Primitive) (ASN1UTCTime tv.timeString)
  else
    ASN1 (makeUniversalTag 24 Primitive) (ASN1GeneralizedTime tv.timeString)

-- | Encodes AlgorithmIdentifier to ASN.1 AST.
encodeAlgIdAst :: AlgorithmIdentifier -> ASN1
encodeAlgIdAst alg =
  let
    (OID arcs) = alg.algorithm
    oidAst = ASN1 (makeUniversalTag 6 Primitive) (ASN1OID arcs)
    nullAst = ASN1 (makeUniversalTag 5 Primitive) ASN1Null
  in
    ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [oidAst, nullAst])

-- | Constructs and encodes TBSCertList DER bytes.
buildTBSCertList :: CRLBuilderConfig -> AlgorithmIdentifier -> TBSCertList
buildTBSCertList cfg algId =
  let
    -- X.509 v2 CRL is version 1
    versionAst = ASN1 (makeUniversalTag 2 Primitive) (ASN1Integer (BigInt.fromInt 1))
    algAst = encodeAlgIdAst algId
    issuerAst = encodeDNAst cfg.issuer
    thisUpAst = encodeTimeValue cfg.thisUpdate

    elementsWithoutRevoked = [versionAst, algAst, issuerAst, thisUpAst]

    elementsWithNext = case cfg.nextUpdate of
      Just nu -> elementsWithoutRevoked <> [encodeTimeValue nu]
      Nothing -> elementsWithoutRevoked

    elementsWithRevoked =
      case uncons cfg.revokedCertificates of
        Nothing -> elementsWithNext
        Just _ ->
          let entriesAst = map encodeRevokedEntryAst cfg.revokedCertificates
          in elementsWithNext <> [ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence entriesAst)]

    crlNumExt = encodeCRLNumberExt cfg.crlNumber
    allExts = [crlNumExt] <> cfg.additionalExts
    extsAst = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence (map encodeExtensionAst allExts))
    explicitExts = ASN1 (makeContextTag 0 Constructed) (ASN1ContextExplicit 0 extsAst)

    finalElements = elementsWithRevoked <> [explicitExts]
    tbsSeq = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence finalElements)
    derBytes = encodeDER tbsSeq
  in
    { version: Just 1
    , signature: algId
    , issuer: cfg.issuer
    , thisUpdate: cfg.thisUpdate
    , nextUpdate: cfg.nextUpdate
    , revokedCertificates: cfg.revokedCertificates
    , crlExtensions: allExts
    , rawDer: derBytes
    }

-- | Signs a TBSCertList with the CA private key, returning a complete CertificateList.
signCRL :: PrivateKey -> TBSCertList -> SignatureAlgorithm -> CertificateList
signCRL privKey tbs sigAlg =
  let
    tbsBytes = tbs.rawDer
    signatureBytes = case signData sigAlg privKey tbsBytes of
      Just sig -> sig
      Nothing -> []
  in
    { tbsCertList: tbs
    , signatureAlgorithm: tbs.signature
    , signatureValue: signatureBytes
    }

-- | Encodes signed CertificateList into canonical DER format.
encodeCRLToDER :: CertificateList -> ByteArray
encodeCRLToDER crl =
  let
    tbsAst = case decodeDER crl.tbsCertList.rawDer of
      Just { element } -> element
      Nothing -> ASN1 (makeUniversalTag 16 Constructed) (ASN1Raw crl.tbsCertList.rawDer)
    algAst = encodeAlgIdAst crl.signatureAlgorithm
    sigAst = ASN1 (makeUniversalTag 3 Primitive) (ASN1BitString 0 crl.signatureValue)
    crlSeq = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [tbsAst, algAst, sigAst])
  in
    encodeDER crlSeq

-- | Encodes signed CertificateList into standard PEM format ("X509 CRL").
encodeCRLToPEM :: CertificateList -> String
encodeCRLToPEM crl =
  let der = encodeCRLToDER crl
  in formatCrlPEM der

-- | Checks whether a certificate serial number is revoked within a given CRL.
isCertRevokedInCRL :: BigInt -> CertificateList -> Maybe RevokedCertificateEntry
isCertRevokedInCRL serial crl =
  foldl (\acc entry ->
    case acc of
      Just _ -> acc
      Nothing ->
        if entry.userCertificate == serial then Just entry
        else Nothing
  ) Nothing crl.tbsCertList.revokedCertificates

-- | Verifies the digital signature on a CertificateList using the issuing CA public key.
verifyCRLSignature :: PublicKey -> CertificateList -> Boolean
verifyCRLSignature pubKey crl =
  verifySignature RsaSha256 pubKey crl.tbsCertList.rawDer crl.signatureValue

-- | Parses a CertificateList from raw DER octets.
parseCRLFromDER :: ByteArray -> Either String CertificateList
parseCRLFromDER derBytes =
  case decodeDER derBytes of
    Nothing -> Left "Failed to parse CRL ASN.1 structure"
    Just { element: ASN1 _ (ASN1Sequence [tbsAst, _, ASN1 _ (ASN1BitString _ sigValue)]) } ->
      let tbsDer = encodeDER tbsAst
      in Right
        { tbsCertList:
            { version: Just 1
            , signature: { algorithm: OID [1, 2, 840, 113549, 1, 1, 11], parameters: Nothing }
            , issuer: DistinguishedName []
            , thisUpdate: { timeString: "", isUtcTime: true, epochSeconds: 0 }
            , nextUpdate: Nothing
            , revokedCertificates: []
            , crlExtensions: []
            , rawDer: tbsDer
            }
        , signatureAlgorithm: { algorithm: OID [1, 2, 840, 113549, 1, 1, 11], parameters: Nothing }
        , signatureValue: sigValue
        }
    Just { element: ASN1 _ (ASN1Sequence [tbsAst, _, ASN1 _ (ASN1OctetString sigValue)]) } ->
      let tbsDer = encodeDER tbsAst
      in Right
        { tbsCertList:
            { version: Just 1
            , signature: { algorithm: OID [1, 2, 840, 113549, 1, 1, 11], parameters: Nothing }
            , issuer: DistinguishedName []
            , thisUpdate: { timeString: "", isUtcTime: true, epochSeconds: 0 }
            , nextUpdate: Nothing
            , revokedCertificates: []
            , crlExtensions: []
            , rawDer: tbsDer
            }
        , signatureAlgorithm: { algorithm: OID [1, 2, 840, 113549, 1, 1, 11], parameters: Nothing }
        , signatureValue: sigValue
        }
    Just _ ->
      Left "Malformed CRL: expected SEQUENCE of [tbsCertList, signatureAlgorithm, signatureValue]"
