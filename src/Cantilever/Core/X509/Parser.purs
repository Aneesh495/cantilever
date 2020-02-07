module Cantilever.Core.X509.Parser
  ( parseCertificateDER
  , parseCertificatePEM
  , parseCertificateBundlePEM
  , decodeAlgorithmIdAst
  , decodeSpkiAst
  ) where

import Prelude

import Cantilever.Core.ASN1.DER (decodeDER, encodeDER)
import Cantilever.Core.ASN1.OID (OID(..))
import Cantilever.Core.ASN1.PEM (decodePEM, decodePEMMany)
import Cantilever.Core.ASN1.Types (ASN1(..), ASN1Tag(..), ASN1Value(..), TagClass(..))
import Cantilever.Core.Crypto.BigInt (BigInt)
import Cantilever.Core.Crypto.BigInt as BigInt
import Cantilever.Core.X509.Extensions (Extension, decodeExtensionAst)
import Cantilever.Core.X509.Name (DistinguishedName, decodeDNAst)
import Cantilever.Core.X509.Types (AlgorithmIdentifier, Certificate, SubjectPublicKeyInfo, TBSCertificate)
import Cantilever.Core.X509.Validity (Validity, decodeValidityAst)
import Data.Array (foldl, uncons)
import Data.Int (fromString)
import Data.Maybe (Maybe(..))

-- | Parses a Certificate from raw DER octets.
parseCertificateDER :: Array Int -> Maybe Certificate
parseCertificateDER bytes =
  case decodeDER bytes of
    Just { element: ASN1 _ (ASN1Sequence topElements) } ->
      case topElements of
        [ tbsAst@(ASN1 _ (ASN1Sequence tbsElements)), sigAlgAst, sigValAst ] -> do
          tbs <- decodeTBSCertificate tbsAst tbsElements
          sigAlg <- decodeAlgorithmIdAst sigAlgAst
          sigBytes <- decodeSignatureBitString sigValAst
          Just
            { tbsCertificate: tbs
            , signatureAlgorithm: sigAlg
            , signatureValue: sigBytes
            , rawDer: bytes
            }
        _ -> Nothing
    _ -> Nothing

-- | Parses a Certificate from a single PEM block.
parseCertificatePEM :: String -> Maybe Certificate
parseCertificatePEM pemStr = do
  { bytes } <- decodePEM pemStr
  parseCertificateDER bytes

-- | Parses an array of Certificates from a multi-block PEM bundle (e.g. certificate fullchain).
parseCertificateBundlePEM :: String -> Array Certificate
parseCertificateBundlePEM pemStr =
  let
    blocks = decodePEMMany pemStr
  in
    foldl (\acc { bytes } ->
      case parseCertificateDER bytes of
        Just cert -> acc <> [ cert ]
        Nothing -> acc
    ) [] blocks

decodeTBSCertificate :: ASN1 -> Array ASN1 -> Maybe TBSCertificate
decodeTBSCertificate fullTbsAst elements = do
  let tbsDerBytes = encodeDER fullTbsAst

  -- Version is optional [0] EXPLICIT INTEGER (defaults to 0 / v1 if absent)
  let { version, rem0 } = extractVersion elements

  -- SerialNumber is next INTEGER
  { serial, rem1 } <- extractSerial rem0

  -- SignatureAlgorithm
  { sigAlg, rem2 } <- extractSigAlg rem1

  -- Issuer Name
  { dn: issuer, rest: rem3 } <- extractName rem2

  -- Validity
  { validity, rem4 } <- extractValidity rem3

  -- Subject Name
  { dn: subject, rest: rem5 } <- extractName rem4

  -- SubjectPublicKeyInfo
  { spki, rest: rem6 } <- extractSpki rem5

  -- Optional Extensions at [3] EXPLICIT
  let extensions = extractExtensions rem6

  Just
    { version: version
    , serialNumber: serial
    , signatureAlgorithm: sigAlg
    , issuer: issuer
    , validity: validity
    , subject: subject
    , subjectPublicKeyInfo: spki
    , extensions: extensions
    , rawDer: tbsDerBytes
    }

extractVersion :: Array ASN1 -> { version :: Int, rem0 :: Array ASN1 }
extractVersion elems =
  case uncons elems of
    Just { head: ASN1 (ASN1Tag { tagClass: ContextSpecific, tagNumber: 0 }) (ASN1ContextExplicit 0 (ASN1 _ (ASN1Integer bi))), tail: rest } ->
      case BigInt.toString bi # fromString of
        Just v -> { version: v, rem0: rest }
        Nothing -> { version: 0, rem0: rest }
    Just { head: ASN1 (ASN1Tag { tagClass: ContextSpecific, tagNumber: 0 }) (ASN1Sequence [ ASN1 _ (ASN1Integer bi) ]), tail: rest } ->
      case BigInt.toString bi # fromString of
        Just v -> { version: v, rem0: rest }
        Nothing -> { version: 0, rem0: rest }
    _ ->
      { version: 0, rem0: elems }

extractSerial :: Array ASN1 -> Maybe { serial :: BigInt, rem1 :: Array ASN1 }
extractSerial elems =
  case uncons elems of
    Just { head: ASN1 _ (ASN1Integer bi), tail: rest } ->
      Just { serial: bi, rem1: rest }
    _ -> Nothing

extractSigAlg :: Array ASN1 -> Maybe { sigAlg :: AlgorithmIdentifier, rem2 :: Array ASN1 }
extractSigAlg elems =
  case uncons elems of
    Just { head: algAst, tail: rest } -> do
      alg <- decodeAlgorithmIdAst algAst
      Just { sigAlg: alg, rem2: rest }
    _ -> Nothing

extractName :: Array ASN1 -> Maybe { dn :: DistinguishedName, rest :: Array ASN1 }
extractName elems =
  case uncons elems of
    Just { head: nameAst, tail: rest } -> do
      dn <- decodeDNAst nameAst
      Just { dn: dn, rest: rest }
    _ -> Nothing

extractValidity :: Array ASN1 -> Maybe { validity :: Validity, rem4 :: Array ASN1 }
extractValidity elems =
  case uncons elems of
    Just { head: valAst, tail: rest } -> do
      val <- decodeValidityAst valAst
      Just { validity: val, rem4: rest }
    _ -> Nothing

extractSpki :: Array ASN1 -> Maybe { spki :: SubjectPublicKeyInfo, rest :: Array ASN1 }
extractSpki elems =
  case uncons elems of
    Just { head: spkiAst, tail: rest } -> do
      spki <- decodeSpkiAst spkiAst
      Just { spki: spki, rest: rest }
    _ -> Nothing

extractExtensions :: Array ASN1 -> Array Extension
extractExtensions elems =
  foldl (\acc el ->
    case el of
      ASN1 (ASN1Tag { tagClass: ContextSpecific, tagNumber: 3 }) (ASN1ContextExplicit 3 (ASN1 _ (ASN1Sequence extAsts))) ->
        foldl (\inner extAst ->
          case decodeExtensionAst extAst of
            Just ext -> inner <> [ ext ]
            Nothing -> inner
        ) acc extAsts
      ASN1 (ASN1Tag { tagClass: ContextSpecific, tagNumber: 3 }) (ASN1Sequence [ ASN1 _ (ASN1Sequence extAsts) ]) ->
        foldl (\inner extAst ->
          case decodeExtensionAst extAst of
            Just ext -> inner <> [ ext ]
            Nothing -> inner
        ) acc extAsts
      _ -> acc
  ) [] elems

-- | Decodes an AlgorithmIdentifier from ASN.1.
decodeAlgorithmIdAst :: ASN1 -> Maybe AlgorithmIdentifier
decodeAlgorithmIdAst (ASN1 _ (ASN1Sequence elems)) =
  case uncons elems of
    Just { head: ASN1 _ (ASN1OID arcs), tail: rest } ->
      let mParams = case uncons rest of
            Just { head: pAst } -> Just pAst
            Nothing -> Nothing
      in Just { algorithm: OID arcs, parameters: mParams }
    _ -> Nothing
decodeAlgorithmIdAst _ = Nothing

-- | Decodes SubjectPublicKeyInfo from ASN.1.
decodeSpkiAst :: ASN1 -> Maybe SubjectPublicKeyInfo
decodeSpkiAst spkiAst@(ASN1 _ (ASN1Sequence [ algAst, ASN1 _ (ASN1BitString _ bits) ])) = do
  alg <- decodeAlgorithmIdAst algAst
  let spkiDer = encodeDER spkiAst
  Just
    { algorithm: alg
    , subjectPublicKey: bits
    , rawDer: spkiDer
    }
decodeSpkiAst _ = Nothing

decodeSignatureBitString :: ASN1 -> Maybe (Array Int)
decodeSignatureBitString (ASN1 _ (ASN1BitString _ bits)) = Just bits
decodeSignatureBitString (ASN1 _ (ASN1OctetString bytes)) = Just bytes
decodeSignatureBitString _ = Nothing
