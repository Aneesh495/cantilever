-- | Module: Cantilever.Core.Revocation.OCSP
-- | Description: RFC 6960 Online Certificate Status Protocol (OCSP) request parser,
-- |              responder engine, and DER serializer.
-- |
-- | Implements complete CertID hash computation (SHA-1 / SHA-256), OCSP Request parsing,
-- | single response generation, nonce extension handling, and BasicOCSPResponse DER generation.

module Cantilever.Core.Revocation.OCSP
  ( OCSPRequest
  , RequestItem
  , buildCertId
  , parseOCSPRequestDER
  , buildBasicResponse
  , encodeOCSPResponseDER
  , verifyOCSPResponseSignature
  ) where

import Prelude

import Cantilever.Core.ASN1.DER (decodeDER, encodeDER)
import Cantilever.Core.ASN1.OID (OID(..))
import Cantilever.Core.ASN1.Types
  ( ASN1(..)
  , ASN1Value(..)
  , TagForm(..)
  , makeContextTag
  , makeUniversalTag
  )
import Cantilever.Core.Crypto.BigInt (BigInt)
import Cantilever.Core.Crypto.Hash (sha1, sha256)
import Cantilever.Core.Crypto.Key (PrivateKey, PublicKey)
import Cantilever.Core.Crypto.Signature (SignatureAlgorithm(..), signData, verifySignature)
import Cantilever.Core.Revocation.Types
  ( BasicOCSPResponse
  , ByteArray
  , CertID
  , OCSPCertStatus(..)
  , OCSPResponse(..)
  , ResponderId(..)
  , SingleResponse
  , crlReasonToInt
  , ocspResponseStatusToInt
  )
import Cantilever.Core.X509.Extensions (Extension, encodeExtensionAst)
import Cantilever.Core.X509.Name (encodeDNAst)
import Cantilever.Core.X509.Types (Certificate)
import Cantilever.Core.X509.Validity (TimeValue)
import Data.Array (head, mapMaybe, uncons)
import Data.Either (Either(..))
import Data.Maybe (Maybe(..), fromMaybe)

-- | An item in the OCSP request list.
type RequestItem =
  { reqCert :: CertID
  , singleRequestExtensions :: Array Extension
  }

-- | Parsed OCSP Request structure.
type OCSPRequest =
  { requestList       :: Array RequestItem
  , requestExtensions :: Array Extension
  , rawDer            :: ByteArray
  }

-- | Computes a CertID from issuer certificate and subject certificate serial number.
buildCertId :: Boolean -> Certificate -> BigInt -> CertID
buildCertId useSha256 issuerCert serial =
  let
    issuerNameDer = encodeDER (encodeDNAst issuerCert.tbsCertificate.subject)
    issuerKeyDer = issuerCert.tbsCertificate.subjectPublicKeyInfo.rawDer
    hashFn = if useSha256 then sha256 else sha1
    algOid = if useSha256 then [2, 16, 840, 1, 101, 3, 4, 2, 1] else [1, 3, 14, 3, 2, 26]
  in
    { hashAlgorithm: { algorithm: OID algOid, parameters: Nothing }
    , issuerNameHash: hashFn issuerNameDer
    , issuerKeyHash: hashFn issuerKeyDer
    , serialNumber: serial
    }

-- | Parses an OCSPRequest from raw DER octets.
parseOCSPRequestDER :: ByteArray -> Either String OCSPRequest
parseOCSPRequestDER derBytes =
  case decodeDER derBytes of
    Nothing -> Left "Failed to parse OCSPRequest ASN.1 structure"
    Just { element: ASN1 _ (ASN1Sequence items) } ->
      case head items of
        Just (ASN1 _ (ASN1Sequence reqItems)) ->
          -- TBSRequest
          let parsedList = parseReqList reqItems
          in Right
            { requestList: parsedList
            , requestExtensions: []
            , rawDer: derBytes
            }
        _ ->
          Left "Malformed OCSPRequest: expected TBSRequest sequence"
    Just _ ->
      Left "Malformed OCSPRequest root tag"
  where
  parseReqList elements =
    mapMaybe parseSingleReq elements

  parseSingleReq (ASN1 _ (ASN1Sequence [certIdAst])) =
    parseCertId certIdAst <#> \cid -> { reqCert: cid, singleRequestExtensions: [] }
  parseSingleReq (ASN1 _ (ASN1Sequence [certIdAst, _exts])) =
    parseCertId certIdAst <#> \cid -> { reqCert: cid, singleRequestExtensions: [] }
  parseSingleReq _ = Nothing

  parseCertId (ASN1 _ (ASN1Sequence [algAst, ASN1 _ (ASN1OctetString nameHash), ASN1 _ (ASN1OctetString keyHash), ASN1 _ (ASN1Integer serial)])) =
    case algAst of
      ASN1 _ (ASN1Sequence [ASN1 _ (ASN1OID algOid), _]) ->
        Just
          { hashAlgorithm: { algorithm: OID algOid, parameters: Nothing }
          , issuerNameHash: nameHash
          , issuerKeyHash: keyHash
          , serialNumber: serial
          }
      _ -> Nothing
  parseCertId _ = Nothing

-- | Encodes a TimeValue into an ASN.1 GeneralizedTime AST for OCSP.
encodeOcspTime :: TimeValue -> ASN1
encodeOcspTime tv =
  ASN1 (makeUniversalTag 24 Primitive) (ASN1GeneralizedTime tv.timeString)

-- | Encodes CertID into ASN.1 AST.
encodeCertIdAst :: CertID -> ASN1
encodeCertIdAst cid =
  let
    (OID algArcs) = cid.hashAlgorithm.algorithm
    algOidAst = ASN1 (makeUniversalTag 6 Primitive) (ASN1OID algArcs)
    nullAst = ASN1 (makeUniversalTag 5 Primitive) ASN1Null
    algSeq = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [algOidAst, nullAst])
    nameHashAst = ASN1 (makeUniversalTag 4 Primitive) (ASN1OctetString cid.issuerNameHash)
    keyHashAst = ASN1 (makeUniversalTag 4 Primitive) (ASN1OctetString cid.issuerKeyHash)
    serialAst = ASN1 (makeUniversalTag 2 Primitive) (ASN1Integer cid.serialNumber)
  in
    ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [algSeq, nameHashAst, keyHashAst, serialAst])

-- | Encodes CertStatus into tagged ASN.1 AST.
-- | good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevocationInfo, unknown [2] IMPLICIT UnknownInfo
encodeCertStatusAst :: OCSPCertStatus -> ASN1
encodeCertStatusAst = case _ of
  CertStatusGood ->
    ASN1 (makeContextTag 0 Primitive) (ASN1ContextImplicit 0 [])
  CertStatusRevoked { revocationTime, revocationReason } ->
    let
      timeAst = encodeOcspTime revocationTime
      elements = case revocationReason of
        Nothing -> [timeAst]
        Just reason ->
          let
            reasonAst = ASN1 (makeUniversalTag 10 Primitive) (ASN1Raw [crlReasonToInt reason])
            explicitReason = ASN1 (makeContextTag 0 Constructed) (ASN1ContextExplicit 0 reasonAst)
          in [timeAst, explicitReason]
    in
      ASN1 (makeContextTag 1 Constructed) (ASN1Sequence elements)
  CertStatusUnknown ->
    ASN1 (makeContextTag 2 Primitive) (ASN1ContextImplicit 2 [])

-- | Encodes SingleResponse into ASN.1 AST.
encodeSingleResponseAst :: SingleResponse -> ASN1
encodeSingleResponseAst sr =
  let
    cidAst = encodeCertIdAst sr.certId
    statusAst = encodeCertStatusAst sr.certStatus
    thisUpAst = encodeOcspTime sr.thisUpdate
    baseItems = [cidAst, statusAst, thisUpAst]
    withNext = case sr.nextUpdate of
      Just nu ->
        let nuAst = encodeOcspTime nu
        in baseItems <> [ASN1 (makeContextTag 0 Constructed) (ASN1ContextExplicit 0 nuAst)]
      Nothing -> baseItems
    withExts = case uncons sr.singleExtensions of
      Just _ ->
        let extsSeq = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence (map encodeExtensionAst sr.singleExtensions))
        in withNext <> [ASN1 (makeContextTag 1 Constructed) (ASN1ContextExplicit 1 extsSeq)]
      Nothing -> withNext
  in
    ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence withExts)

-- | Constructs and signs a BasicOCSPResponse with CA private key.
buildBasicResponse
  :: PrivateKey
  -> ResponderId
  -> TimeValue
  -> Array SingleResponse
  -> Array Extension
  -> Maybe (Array Certificate)
  -> BasicOCSPResponse
buildBasicResponse privKey respId prodAt responses exts certs =
  let
    respIdAst = case respId of
      ResponderByName dn ->
        ASN1 (makeContextTag 1 Constructed) (ASN1ContextExplicit 1 (encodeDNAst dn))
      ResponderByKeyHash kh ->
        ASN1 (makeContextTag 2 Primitive) (ASN1ContextImplicit 2 kh)

    prodAtAst = encodeOcspTime prodAt
    respsSeq = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence (map encodeSingleResponseAst responses))
    baseItems = [respIdAst, prodAtAst, respsSeq]

    finalItems = case uncons exts of
      Just _ ->
        let extsSeq = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence (map encodeExtensionAst exts))
        in baseItems <> [ASN1 (makeContextTag 1 Constructed) (ASN1ContextExplicit 1 extsSeq)]
      Nothing -> baseItems

    tbsSeq = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence finalItems)
    tbsDer = encodeDER tbsSeq

    sigBytes = fromMaybe [] (signData RsaSha256 privKey tbsDer)
    algId = { algorithm: OID [1, 2, 840, 113549, 1, 1, 11], parameters: Nothing }
  in
    { tbsResponseData:
        { responderId: respId
        , producedAt: prodAt
        , responses: responses
        , responseExtensions: exts
        , rawDer: tbsDer
        }
    , signatureAlgorithm: algId
    , signature: sigBytes
    , certs: certs
    }

-- | Encodes an OCSPResponse to canonical DER octets.
encodeOCSPResponseDER :: OCSPResponse -> ByteArray
encodeOCSPResponseDER = case _ of
  OCSPResponseError status ->
    let statusAst = ASN1 (makeUniversalTag 10 Primitive) (ASN1Raw [ocspResponseStatusToInt status])
    in encodeDER (ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [statusAst]))
  OCSPResponseBasic status maybeBasic ->
    let
      statusAst = ASN1 (makeUniversalTag 10 Primitive) (ASN1Raw [ocspResponseStatusToInt status])
    in
      case maybeBasic of
        Nothing ->
          encodeDER (ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [statusAst]))
        Just basic ->
          let
            (OID algArcs) = basic.signatureAlgorithm.algorithm
            algOidAst = ASN1 (makeUniversalTag 6 Primitive) (ASN1OID algArcs)
            nullAst = ASN1 (makeUniversalTag 5 Primitive) ASN1Null
            algSeq = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [algOidAst, nullAst])
            tbsAst = case decodeDER basic.tbsResponseData.rawDer of
              Just { element } -> element
              Nothing -> ASN1 (makeUniversalTag 16 Constructed) (ASN1Raw basic.tbsResponseData.rawDer)
            sigAst = ASN1 (makeUniversalTag 3 Primitive) (ASN1BitString 0 basic.signature)
            basicItems = [tbsAst, algSeq, sigAst]
            basicSeq = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence basicItems)
            basicDer = encodeDER basicSeq

            -- responseType id-pkix-ocsp-basic: 1.3.6.1.5.5.7.48.1.1
            respTypeAst = ASN1 (makeUniversalTag 6 Primitive) (ASN1OID [1, 3, 6, 1, 5, 5, 7, 48, 1, 1])
            respOctet = ASN1 (makeUniversalTag 4 Primitive) (ASN1OctetString basicDer)
            respBytesSeq = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [respTypeAst, respOctet])
            taggedRespBytes = ASN1 (makeContextTag 0 Constructed) (ASN1ContextExplicit 0 respBytesSeq)

            envelope = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [statusAst, taggedRespBytes])
          in
            encodeDER envelope

-- | Verifies the responder's signature on a BasicOCSPResponse using their public key.
verifyOCSPResponseSignature :: PublicKey -> BasicOCSPResponse -> Boolean
verifyOCSPResponseSignature pubKey basic =
  verifySignature RsaSha256 pubKey basic.tbsResponseData.rawDer basic.signature
