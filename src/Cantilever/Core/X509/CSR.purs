module Cantilever.Core.X509.CSR
  ( CertificationRequestInfo
  , CertificationRequest
  , buildCSR
  , parseCSRDER
  , parseCSRPEM
  , encodeCSRDER
  , verifyCSRSignature
  , getCsrSANs
  , getCsrPublicKey
  ) where

import Prelude

import Cantilever.Core.ASN1.DER (decodeDER, encodeDER)
import Cantilever.Core.ASN1.OID (OID(..), extSubjectAltName, sha256WithRSAEncryption)
import Cantilever.Core.ASN1.PEM (decodePEM)
import Cantilever.Core.ASN1.Types
  ( ASN1(..)
  , ASN1Tag(..)
  , ASN1Value(..)
  , TagClass(..)
  , TagForm(..)
  , makeUniversalTag
  )
import Cantilever.Core.Crypto.BigInt (fromInt)
import Cantilever.Core.Crypto.Key (KeyAlgorithm(..), KeyPair, PublicKey)
import Cantilever.Core.Crypto.Signature (SignatureAlgorithm(..), signData, verifySignature)
import Cantilever.Core.X509.Extensions (Extension, ExtensionValue(..), GeneralName(..), decodeExtensionAst, encodeExtensionAst)
import Cantilever.Core.X509.Name (DistinguishedName, decodeDNAst, encodeDNAst)
import Cantilever.Core.X509.Parser (decodeAlgorithmIdAst, decodeSpkiAst)
import Cantilever.Core.X509.Types (AlgorithmIdentifier, SubjectPublicKeyInfo, makeAlgorithmIdentifier)
import Data.Array (foldl, uncons)
import Data.Maybe (Maybe(..))

-- | PKCS#10 CertificationRequestInfo per RFC 2986 Section 4.1.
type CertificationRequestInfo =
  { version :: Int
  , subject :: DistinguishedName
  , subjectPublicKeyInfo :: SubjectPublicKeyInfo
  , extensions :: Array Extension
  , rawDer :: Array Int
  }

-- | Complete PKCS#10 CertificationRequest.
type CertificationRequest =
  { certificationRequestInfo :: CertificationRequestInfo
  , signatureAlgorithm :: AlgorithmIdentifier
  , signatureValue :: Array Int
  , rawDer :: Array Int
  }

-- | Encodes CertificationRequestInfo into an ASN.1 Structure.
encodeCSRInfoAst :: CertificationRequestInfo -> ASN1
encodeCSRInfoAst info =
  let
    seqTag = makeUniversalTag 16 Constructed
    verAst = ASN1 (makeUniversalTag 2 Primitive) (ASN1Integer (fromInt info.version))
    subjectAst = encodeDNAst info.subject
    spkiAst = encodeSpkiAst info.subjectPublicKeyInfo

    -- extensionRequest attribute at OID 1.2.840.113549.1.9.14 in [0] Attributes context tag
    extSeqAst = ASN1 (makeUniversalTag 16 Constructed)
      (info.extensions <#> encodeExtensionAst # ASN1Sequence)
    extReqOidAst = ASN1 (makeUniversalTag 6 Primitive) (ASN1OID [ 1, 2, 840, 113549, 1, 9, 14 ])
    extReqSetAst = ASN1 (makeUniversalTag 17 Constructed) (ASN1Set [ extSeqAst ])
    extReqAttrAst = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [ extReqOidAst, extReqSetAst ])

    attrContainerAst = ASN1 (ASN1Tag { tagClass: ContextSpecific, tagForm: Constructed, tagNumber: 0 })
      (ASN1Sequence [ extReqAttrAst ])
  in
    ASN1 seqTag (ASN1Sequence [ verAst, subjectAst, spkiAst, attrContainerAst ])

encodeAlgorithmIdAst :: AlgorithmIdentifier -> ASN1
encodeAlgorithmIdAst alg =
  let
    (OID arcs) = alg.algorithm
    oidAst = ASN1 (makeUniversalTag 6 Primitive) (ASN1OID arcs)
    nullAst = ASN1 (makeUniversalTag 5 Primitive) ASN1Null
  in
    ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [ oidAst, nullAst ])

encodeSpkiAst :: SubjectPublicKeyInfo -> ASN1
encodeSpkiAst spki =
  let
    algAst = encodeAlgorithmIdAst spki.algorithm
    bitStringAst = ASN1 (makeUniversalTag 3 Primitive) (ASN1BitString 0 spki.subjectPublicKey)
  in
    ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [ algAst, bitStringAst ])

-- | Encodes a complete CertificationRequest to DER.
encodeCSRDER :: CertificationRequest -> Array Int
encodeCSRDER csr =
  let
    infoAst = encodeCSRInfoAst csr.certificationRequestInfo
    sigAlgAst = encodeAlgorithmIdAst csr.signatureAlgorithm
    sigBitsAst = ASN1 (makeUniversalTag 3 Primitive) (ASN1BitString 0 csr.signatureValue)
    csrAst = ASN1 (makeUniversalTag 16 Constructed)
      (ASN1Sequence [ infoAst, sigAlgAst, sigBitsAst ])
  in
    encodeDER csrAst

-- | Builds and self-signs a PKCS#10 CSR with requested subject DN and SAN DNS names.
buildCSR
  :: DistinguishedName
  -> Array String
  -> KeyPair
  -> Maybe CertificationRequest
buildCSR subject sans keyPair = do
  let
    sanGeneralNames = sans <#> DnsName
    exts = if sans == [] then []
           else
             [ { oid: extSubjectAltName
               , critical: false
               , value: SubjectAltName sanGeneralNames
               }
             ]
    spki :: SubjectPublicKeyInfo
    spki =
      { algorithm: makeAlgorithmIdentifier sha256WithRSAEncryption
      , subjectPublicKey: keyPair.publicKey.rawSpki
      , rawDer: keyPair.publicKey.rawSpki
      }
    infoNoDer :: CertificationRequestInfo
    infoNoDer =
      { version: 0
      , subject: subject
      , subjectPublicKeyInfo: spki
      , extensions: exts
      , rawDer: []
      }
    infoAst = encodeCSRInfoAst infoNoDer
    infoDer = encodeDER infoAst
    info = infoNoDer { rawDer = infoDer }

  sigBytes <- signData RsaSha256 keyPair.privateKey infoDer
  let
    csr =
      { certificationRequestInfo: info
      , signatureAlgorithm: makeAlgorithmIdentifier sha256WithRSAEncryption
      , signatureValue: sigBytes
      , rawDer: []
      }
    fullDer = encodeCSRDER csr
  Just (csr { rawDer = fullDer })

-- | Parses a PKCS#10 CSR from DER octets.
parseCSRDER :: Array Int -> Maybe CertificationRequest
parseCSRDER bytes =
  case decodeDER bytes of
    Just { element: ASN1 _ (ASN1Sequence [ infoAst@(ASN1 _ (ASN1Sequence infoElems)), sigAlgAst, sigValAst ]) } -> do
      info <- decodeCSRInfo infoAst infoElems
      sigAlg <- decodeAlgorithmIdAst sigAlgAst
      sigBytes <- decodeSignatureBitString sigValAst
      Just
        { certificationRequestInfo: info
        , signatureAlgorithm: sigAlg
        , signatureValue: sigBytes
        , rawDer: bytes
        }
    _ -> Nothing

-- | Parses a PKCS#10 CSR from a PEM string.
parseCSRPEM :: String -> Maybe CertificationRequest
parseCSRPEM pemStr = do
  { bytes } <- decodePEM pemStr
  parseCSRDER bytes

decodeCSRInfo :: ASN1 -> Array ASN1 -> Maybe CertificationRequestInfo
decodeCSRInfo fullInfoAst elems = do
  let infoDer = encodeDER fullInfoAst
  { tail: r1 } <- uncons elems
  { head: subjectAst, tail: r2 } <- uncons r1
  { head: spkiAst, tail: rest } <- uncons r2
  dn <- decodeDNAst subjectAst
  spki <- decodeSpkiAst spkiAst
  let exts = extractCsrExtensions rest
  Just
    { version: 0
    , subject: dn
    , subjectPublicKeyInfo: spki
    , extensions: exts
    , rawDer: infoDer
    }

extractCsrExtensions :: Array ASN1 -> Array Extension
extractCsrExtensions elems =
  foldl (\acc el ->
    case el of
      ASN1 (ASN1Tag { tagClass: ContextSpecific, tagNumber: 0 }) (ASN1Sequence attrElems) ->
        foldl (\inner attr ->
          case attr of
            ASN1 _ (ASN1Sequence [ ASN1 _ (ASN1OID [ 1, 2, 840, 113549, 1, 9, 14 ]), ASN1 _ (ASN1Set [ ASN1 _ (ASN1Sequence extAsts) ]) ]) ->
              foldl (\sub extAst ->
                case decodeExtensionAst extAst of
                  Just ext -> sub <> [ ext ]
                  Nothing -> sub
              ) inner extAsts
            _ -> inner
        ) acc attrElems
      _ -> acc
  ) [] elems

decodeSignatureBitString :: ASN1 -> Maybe (Array Int)
decodeSignatureBitString (ASN1 _ (ASN1BitString _ bits)) = Just bits
decodeSignatureBitString (ASN1 _ (ASN1OctetString bytes)) = Just bytes
decodeSignatureBitString _ = Nothing

-- | Cryptographically verifies the applicant's self-signature on the CSR (Proof of Possession).
verifyCSRSignature :: CertificationRequest -> Boolean
verifyCSRSignature csr =
  let
    spki = csr.certificationRequestInfo.subjectPublicKeyInfo
    pubKey :: PublicKey
    pubKey =
      { algorithm: RSA2048 -- default type
      , rawSpki: spki.rawDer
      }
    dataBytes = csr.certificationRequestInfo.rawDer
    sigBytes = csr.signatureValue
  in
    verifySignature RsaSha256 pubKey dataBytes sigBytes

-- | Extracts all SAN DNS names requested in a CSR.
getCsrSANs :: CertificationRequest -> Array String
getCsrSANs csr =
  foldl (\acc ext ->
    case ext.value of
      SubjectAltName names ->
        foldl (\inner gn ->
          case gn of
            DnsName s -> inner <> [ s ]
            _ -> inner
        ) acc names
      _ -> acc
  ) [] csr.certificationRequestInfo.extensions

-- | Extracts the raw public key bytes from a CSR.
getCsrPublicKey :: CertificationRequest -> PublicKey
getCsrPublicKey csr =
  { algorithm: RSA2048
  , rawSpki: csr.certificationRequestInfo.subjectPublicKeyInfo.rawDer
  }
