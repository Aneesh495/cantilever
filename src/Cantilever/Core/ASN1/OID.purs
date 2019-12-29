module Cantilever.Core.ASN1.OID
  ( OID(..)
  , parseOID
  , formatOID
  , encodeOIDDer
  , decodeOIDDer
  , oidName
  , isPrefixOf
  -- Cryptographic Algorithms
  , rsaEncryption
  , sha256WithRSAEncryption
  , sha384WithRSAEncryption
  , idRsassaPss
  , idEcPublicKey
  , secp256r1
  , secp384r1
  , ecdsaWithSHA256
  , ecdsaWithSHA384
  , idEd25519
  , sha256Oid
  , sha384Oid
  , sha512Oid
  -- X.500 Attributes
  , atCommonName
  , atCountryName
  , atLocalityName
  , atStateOrProvinceName
  , atOrganizationName
  , atOrganizationalUnitName
  , atSerialNumber
  -- X.509 v3 Extensions
  , extBasicConstraints
  , extKeyUsage
  , extExtKeyUsage
  , extSubjectAltName
  , extIssuerAltName
  , extAuthorityKeyIdentifier
  , extSubjectKeyIdentifier
  , extCrlDistributionPoints
  , extAuthorityInfoAccess
  , extNameConstraints
  , extCertificatePolicies
  , extPrecertPoison
  , extEmbeddedSctList
  -- Extended Key Usages
  , ekuServerAuth
  , ekuClientAuth
  , ekuCodeSigning
  , ekuEmailProtection
  , ekuTimeStamping
  , ekuOcspSigning
  -- Authority Info Access Methods
  , aiaOcsp
  , aiaCaIssuers
  ) where

import Prelude

import Data.Array ((..), (!!), cons, foldl, length, slice, uncons)
import Data.Int (fromString)
import Data.Int.Bits ((.&.), (.|.), shl, zshr)
import Data.Maybe (Maybe(..), fromMaybe)
import Data.String.Common (split)
import Data.String.Pattern (Pattern(..))

-- | ASN.1 Object Identifier represented as an array of arc integers.
newtype OID = OID (Array Int)

derive instance eqOID :: Eq OID
derive instance ordOID :: Ord OID

instance showOID :: Show OID where
  show = formatOID

-- | Formats an OID into its canonical dotted decimal string representation: "1.2.840..."
formatOID :: OID -> String
formatOID (OID arcs) =
  case uncons arcs of
    Nothing -> ""
    Just { head, tail } ->
      foldl (\acc x -> acc <> "." <> show x) (show head) tail

-- | Parses a dotted decimal string into an OID.
parseOID :: String -> Maybe OID
parseOID str =
  let
    tokens = split (Pattern ".") str
    mArcs = tokens <#> fromString
  in
    if length tokens < 2 then
      Nothing
    else
      sequenceMaybes mArcs <#> OID
  where
  sequenceMaybes = foldl (\acc mx ->
    case acc, mx of
      Just xs, Just x -> Just (xs <> [ x ])
      _, _ -> Nothing
  ) (Just [])

-- | Checks if an OID is a prefix of another OID.
isPrefixOf :: OID -> OID -> Boolean
isPrefixOf (OID pfx) (OID full) =
  let pLen = length pfx
      fLen = length full
  in if pLen > fLen then false
     else slice 0 pLen full == pfx

-- | Encodes an OID into DER octets according to ITU-T X.690 Section 8.19.
encodeOIDDer :: OID -> Array Int
encodeOIDDer (OID arcs) =
  case arcs of
    [ a, b ] -> encodeFirstTwo a b
    _ ->
      case uncons arcs of
        Just { head: a, tail: r1 } ->
          case uncons r1 of
            Just { head: b, tail: rest } ->
              let firstOctet = encodeFirstTwo a b
                  restOctets = foldl (\acc arc -> acc <> encodeVlq arc) [] rest
              in firstOctet <> restOctets
            Nothing -> []
        Nothing -> []
  where
  encodeFirstTwo a b = [ a * 40 + b ]

  encodeVlq val =
    if val == 0 then [ 0 ]
    else
      let bytes = go [] val
      in markContinuation bytes
    where
    go acc 0 = acc
    go acc v =
      let chunk = v .&. 0x7f
      in go (cons chunk acc) (zshr v 7)

    markContinuation bs =
      let n = length bs
      in mapWithIndex (\i b -> if i == n - 1 then b else b .|. 0x80) bs

    mapWithIndex f arr =
      (0 .. (length arr - 1)) <#> \i -> f i (fromMaybe 0 (arr !! i))

-- | Decodes an OID from DER payload octets.
decodeOIDDer :: Array Int -> Maybe OID
decodeOIDDer bytes =
  case uncons bytes of
    Nothing -> Nothing
    Just { head: firstByte, tail: rest } ->
      let
        firstArc = firstByte / 40
        secondArc = firstByte `mod` 40
        mRemainingArcs = decodeVlqs [] 0 rest
      in
        mRemainingArcs <#> \remArcs -> OID (cons firstArc (cons secondArc remArcs))
  where
  decodeVlqs acc current remBytes =
    case uncons remBytes of
      Nothing ->
        if current == 0 && length acc > 0 then Just acc
        else if length acc == 0 && current == 0 then Just []
        else Nothing
      Just { head: x, tail: xs } ->
        let
          newCurrent = (shl current 7) .|. (x .&. 0x7f)
          isLast = (x .&. 0x80) == 0
        in
          if isLast then
            decodeVlqs (acc <> [ newCurrent ]) 0 xs
          else
            decodeVlqs acc newCurrent xs

-- Cryptographic Algorithms
rsaEncryption :: OID
rsaEncryption = OID [ 1, 2, 840, 113549, 1, 1, 1 ]

sha256WithRSAEncryption :: OID
sha256WithRSAEncryption = OID [ 1, 2, 840, 113549, 1, 1, 11 ]

sha384WithRSAEncryption :: OID
sha384WithRSAEncryption = OID [ 1, 2, 840, 113549, 1, 1, 12 ]

idRsassaPss :: OID
idRsassaPss = OID [ 1, 2, 840, 113549, 1, 1, 10 ]

idEcPublicKey :: OID
idEcPublicKey = OID [ 1, 2, 840, 10045, 2, 1 ]

secp256r1 :: OID
secp256r1 = OID [ 1, 2, 840, 10045, 3, 1, 7 ]

secp384r1 :: OID
secp384r1 = OID [ 1, 3, 132, 0, 34 ]

ecdsaWithSHA256 :: OID
ecdsaWithSHA256 = OID [ 1, 2, 840, 10045, 4, 3, 2 ]

ecdsaWithSHA384 :: OID
ecdsaWithSHA384 = OID [ 1, 2, 840, 10045, 4, 3, 3 ]

idEd25519 :: OID
idEd25519 = OID [ 1, 3, 101, 112 ]

sha256Oid :: OID
sha256Oid = OID [ 2, 16, 840, 1, 101, 3, 4, 2, 1 ]

sha384Oid :: OID
sha384Oid = OID [ 2, 16, 840, 1, 101, 3, 4, 2, 2 ]

sha512Oid :: OID
sha512Oid = OID [ 2, 16, 840, 1, 101, 3, 4, 2, 3 ]

-- X.500 Attribute Types (RFC 4519, RFC 5280)
atCommonName :: OID
atCommonName = OID [ 2, 5, 4, 3 ]

atCountryName :: OID
atCountryName = OID [ 2, 5, 4, 6 ]

atLocalityName :: OID
atLocalityName = OID [ 2, 5, 4, 7 ]

atStateOrProvinceName :: OID
atStateOrProvinceName = OID [ 2, 5, 4, 8 ]

atOrganizationName :: OID
atOrganizationName = OID [ 2, 5, 4, 10 ]

atOrganizationalUnitName :: OID
atOrganizationalUnitName = OID [ 2, 5, 4, 11 ]

atSerialNumber :: OID
atSerialNumber = OID [ 2, 5, 4, 5 ]

-- X.509 v3 Extensions (RFC 5280)
extBasicConstraints :: OID
extBasicConstraints = OID [ 2, 5, 29, 19 ]

extKeyUsage :: OID
extKeyUsage = OID [ 2, 5, 29, 15 ]

extExtKeyUsage :: OID
extExtKeyUsage = OID [ 2, 5, 29, 37 ]

extSubjectAltName :: OID
extSubjectAltName = OID [ 2, 5, 29, 17 ]

extIssuerAltName :: OID
extIssuerAltName = OID [ 2, 5, 29, 18 ]

extAuthorityKeyIdentifier :: OID
extAuthorityKeyIdentifier = OID [ 2, 5, 29, 35 ]

extSubjectKeyIdentifier :: OID
extSubjectKeyIdentifier = OID [ 2, 5, 29, 14 ]

extCrlDistributionPoints :: OID
extCrlDistributionPoints = OID [ 2, 5, 29, 31 ]

extAuthorityInfoAccess :: OID
extAuthorityInfoAccess = OID [ 1, 3, 6, 1, 5, 5, 7, 1, 1 ]

extNameConstraints :: OID
extNameConstraints = OID [ 2, 5, 29, 30 ]

extCertificatePolicies :: OID
extCertificatePolicies = OID [ 2, 5, 29, 32 ]

-- Certificate Transparency (RFC 6962)
extPrecertPoison :: OID
extPrecertPoison = OID [ 1, 3, 6, 1, 4, 1, 11129, 2, 4, 3 ]

extEmbeddedSctList :: OID
extEmbeddedSctList = OID [ 1, 3, 6, 1, 4, 1, 11129, 2, 4, 2 ]

-- Extended Key Usage (RFC 5280)
ekuServerAuth :: OID
ekuServerAuth = OID [ 1, 3, 6, 1, 5, 5, 7, 3, 1 ]

ekuClientAuth :: OID
ekuClientAuth = OID [ 1, 3, 6, 1, 5, 5, 7, 3, 2 ]

ekuCodeSigning :: OID
ekuCodeSigning = OID [ 1, 3, 6, 1, 5, 5, 7, 3, 3 ]

ekuEmailProtection :: OID
ekuEmailProtection = OID [ 1, 3, 6, 1, 5, 5, 7, 3, 4 ]

ekuTimeStamping :: OID
ekuTimeStamping = OID [ 1, 3, 6, 1, 5, 5, 7, 3, 8 ]

ekuOcspSigning :: OID
ekuOcspSigning = OID [ 1, 3, 6, 1, 5, 5, 7, 3, 9 ]

-- Authority Info Access Methods
aiaOcsp :: OID
aiaOcsp = OID [ 1, 3, 6, 1, 5, 5, 7, 48, 1 ]

aiaCaIssuers :: OID
aiaCaIssuers = OID [ 1, 3, 6, 1, 5, 5, 7, 48, 2 ]

-- | Human-readable name for well-known OIDs.
oidName :: OID -> String
oidName oid
  | oid == rsaEncryption = "rsaEncryption"
  | oid == sha256WithRSAEncryption = "sha256WithRSAEncryption"
  | oid == sha384WithRSAEncryption = "sha384WithRSAEncryption"
  | oid == idRsassaPss = "id-rsassa-pss"
  | oid == idEcPublicKey = "id-ecPublicKey"
  | oid == secp256r1 = "secp256r1"
  | oid == secp384r1 = "secp384r1"
  | oid == ecdsaWithSHA256 = "ecdsa-with-SHA256"
  | oid == ecdsaWithSHA384 = "ecdsa-with-SHA384"
  | oid == idEd25519 = "id-Ed25519"
  | oid == sha256Oid = "id-sha256"
  | oid == sha384Oid = "id-sha384"
  | oid == sha512Oid = "id-sha512"
  | oid == atCommonName = "commonName"
  | oid == atCountryName = "countryName"
  | oid == atLocalityName = "localityName"
  | oid == atStateOrProvinceName = "stateOrProvinceName"
  | oid == atOrganizationName = "organizationName"
  | oid == atOrganizationalUnitName = "organizationalUnitName"
  | oid == atSerialNumber = "serialNumber"
  | oid == extBasicConstraints = "basicConstraints"
  | oid == extKeyUsage = "keyUsage"
  | oid == extExtKeyUsage = "extKeyUsage"
  | oid == extSubjectAltName = "subjectAltName"
  | oid == extIssuerAltName = "issuerAltName"
  | oid == extAuthorityKeyIdentifier = "authorityKeyIdentifier"
  | oid == extSubjectKeyIdentifier = "subjectKeyIdentifier"
  | oid == extCrlDistributionPoints = "cRLDistributionPoints"
  | oid == extAuthorityInfoAccess = "authorityInfoAccess"
  | oid == extNameConstraints = "nameConstraints"
  | oid == extCertificatePolicies = "certificatePolicies"
  | oid == extPrecertPoison = "precertificatePoison"
  | oid == extEmbeddedSctList = "embeddedSCTList"
  | oid == ekuServerAuth = "serverAuth"
  | oid == ekuClientAuth = "clientAuth"
  | oid == ekuCodeSigning = "codeSigning"
  | oid == ekuEmailProtection = "emailProtection"
  | oid == ekuTimeStamping = "timeStamping"
  | oid == ekuOcspSigning = "ocspSigning"
  | oid == aiaOcsp = "ocsp"
  | oid == aiaCaIssuers = "caIssuers"
  | otherwise = formatOID oid
