module Cantilever.Core.X509.Extensions
  ( GeneralName(..)
  , GeneralSubtree(..)
  , KeyUsageFlag(..)
  , ExtensionValue(..)
  , Extension
  , encodeExtensionAst
  , decodeExtensionAst
  , findExtension
  , hasKeyUsage
  , getSanDnsNames
  , getSanIpAddresses
  , isCaExtension
  , getPathLenConstraint
  ) where

import Prelude

import Cantilever.Core.ASN1.DER (decodeDER, decodeIntegerDER, encodeDER, encodeIntegerDER)
import Cantilever.Core.ASN1.OID
  ( OID(..)
  , extAuthorityKeyIdentifier
  , extBasicConstraints
  , extEmbeddedSctList
  , extExtKeyUsage
  , extIssuerAltName
  , extKeyUsage
  , extPrecertPoison
  , extSubjectAltName
  , extSubjectKeyIdentifier
  )
import Cantilever.Core.ASN1.Types
  ( ASN1(..)
  , ASN1Tag(..)
  , ASN1Value(..)
  , TagClass(..)
  , TagForm(..)
  , makeUniversalTag
  )
import Cantilever.Core.Crypto.BigInt (BigInt, fromInt)
import Cantilever.Core.Crypto.BigInt as BigInt
import Data.Array (foldl, length, uncons, (!!))
import Data.Int (fromString)
import Data.Int.Bits ((.&.), (.|.))
import Data.Maybe (Maybe(..), fromMaybe)
import Data.String.CodeUnits (fromCharArray, toCharArray)

-- | GeneralName according to RFC 5280 Section 4.2.1.6.
data GeneralName
  = DnsName String
  | IpAddress (Array Int)
  | Rfc822Name String
  | Uri String

derive instance eqGeneralName :: Eq GeneralName
derive instance ordGeneralName :: Ord GeneralName

instance showGeneralName :: Show GeneralName where
  show = case _ of
    DnsName dns -> "DNS:" <> dns
    IpAddress ip -> "IP:" <> formatIp ip
    Rfc822Name email -> "email:" <> email
    Uri u -> "URI:" <> u
    where
    formatIp bytes =
      case uncons bytes of
        Nothing -> ""
        Just { head, tail } ->
          foldl (\acc b -> acc <> "." <> show b) (show head) tail

-- | GeneralSubtree representing base constraint with optional min/max distance.
data GeneralSubtree = GeneralSubtree
  { base :: GeneralName
  , minimum :: Int
  , maximum :: Maybe Int
  }

derive instance eqGeneralSubtree :: Eq GeneralSubtree
derive instance ordGeneralSubtree :: Ord GeneralSubtree

-- | Key Usage flags per RFC 5280 Section 4.2.1.3.
data KeyUsageFlag
  = DigitalSignature
  | NonRepudiation
  | KeyEncipherment
  | DataEncipherment
  | KeyAgreement
  | KeyCertSign
  | CRLSign
  | EncipherOnly
  | DecipherOnly

derive instance eqKeyUsageFlag :: Eq KeyUsageFlag
derive instance ordKeyUsageFlag :: Ord KeyUsageFlag

instance showKeyUsageFlag :: Show KeyUsageFlag where
  show = case _ of
    DigitalSignature -> "digitalSignature"
    NonRepudiation -> "nonRepudiation"
    KeyEncipherment -> "keyEncipherment"
    DataEncipherment -> "dataEncipherment"
    KeyAgreement -> "keyAgreement"
    KeyCertSign -> "keyCertSign"
    CRLSign -> "cRLSign"
    EncipherOnly -> "encipherOnly"
    DecipherOnly -> "decipherOnly"

-- | Strongly-typed representations of standard X.509 v3 extensions.
data ExtensionValue
  = BasicConstraints { isCA :: Boolean, pathLenConstraint :: Maybe Int }
  | KeyUsage (Array KeyUsageFlag)
  | ExtKeyUsage (Array OID)
  | SubjectAltName (Array GeneralName)
  | IssuerAltName (Array GeneralName)
  | SubjectKeyIdentifier (Array Int)
  | AuthorityKeyIdentifier
      { keyIdentifier :: Maybe (Array Int)
      , authorityCertSerialNumber :: Maybe BigInt
      }
  | AuthorityInfoAccess (Array { accessMethod :: OID, accessLocation :: GeneralName })
  | CrlDistributionPoints (Array GeneralName)
  | NameConstraints
      { permittedSubtrees :: Array GeneralSubtree
      , excludedSubtrees :: Array GeneralSubtree
      }
  | CertificatePolicies (Array OID)
  | PrecertificatePoison
  | EmbeddedSctList (Array Int)
  | RawExtension (Array Int)

derive instance eqExtensionValue :: Eq ExtensionValue

-- | Full Extension record containing OID, criticality flag, and parsed value.
type Extension =
  { oid :: OID
  , critical :: Boolean
  , value :: ExtensionValue
  }

-- | Encodes an Extension into an ASN.1 Sequence [ OID, Boolean(opt), OctetString ].
encodeExtensionAst :: Extension -> ASN1
encodeExtensionAst ext =
  let
    seqTag = makeUniversalTag 16 Constructed
    (OID arcs) = ext.oid
    oidAst = ASN1 (makeUniversalTag 6 Primitive) (ASN1OID arcs)
    payloadBytes = encodeExtensionValueDER ext.value
    octetAst = ASN1 (makeUniversalTag 4 Primitive) (ASN1OctetString payloadBytes)
    elements =
      if ext.critical then
        let critAst = ASN1 (makeUniversalTag 1 Primitive) (ASN1Boolean true)
        in [ oidAst, critAst, octetAst ]
      else
        [ oidAst, octetAst ]
  in
    ASN1 seqTag (ASN1Sequence elements)

-- | Encodes ExtensionValue to DER octets.
encodeExtensionValueDER :: ExtensionValue -> Array Int
encodeExtensionValueDER = case _ of
  BasicConstraints { isCA, pathLenConstraint } ->
    let
      caAst = if isCA then [ ASN1 (makeUniversalTag 1 Primitive) (ASN1Boolean true) ] else []
      pathAst = case pathLenConstraint of
        Just n -> [ ASN1 (makeUniversalTag 2 Primitive) (ASN1Integer (fromInt n)) ]
        Nothing -> []
      seqAst = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence (caAst <> pathAst))
    in
      encodeDER seqAst

  KeyUsage flags ->
    let
      byte0 = foldl (\acc f -> acc .|. flagBit f) 0 flags
      byte1 = foldl (\acc f -> acc .|. flagBitHigh f) 0 flags
      unusedBits = 7 -- 9 bits used out of 16 bits = 7 unused bits
      bitStringAst = ASN1 (makeUniversalTag 3 Primitive) (ASN1BitString unusedBits [ byte0, byte1 ])
    in
      encodeDER bitStringAst

  ExtKeyUsage oids ->
    let
      oidAsts = oids <#> \(OID arcs) -> ASN1 (makeUniversalTag 6 Primitive) (ASN1OID arcs)
      seqAst = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence oidAsts)
    in
      encodeDER seqAst

  SubjectAltName names ->
    let
      nameAsts = names <#> encodeGeneralNameAst
      seqAst = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence nameAsts)
    in
      encodeDER seqAst

  IssuerAltName names ->
    let
      nameAsts = names <#> encodeGeneralNameAst
      seqAst = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence nameAsts)
    in
      encodeDER seqAst

  SubjectKeyIdentifier keyId ->
    let octetAst = ASN1 (makeUniversalTag 4 Primitive) (ASN1OctetString keyId)
    in encodeDER octetAst

  AuthorityKeyIdentifier { keyIdentifier, authorityCertSerialNumber } ->
    let
      keyIdAst = case keyIdentifier of
        Just kid -> [ ASN1 (ASN1Tag { tagClass: ContextSpecific, tagForm: Primitive, tagNumber: 0 }) (ASN1ContextImplicit 0 kid) ]
        Nothing -> []
      serialAst = case authorityCertSerialNumber of
        Just sn -> [ ASN1 (ASN1Tag { tagClass: ContextSpecific, tagForm: Primitive, tagNumber: 2 }) (ASN1ContextImplicit 2 (encodeIntegerDER sn)) ]
        Nothing -> []
      seqAst = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence (keyIdAst <> serialAst))
    in
      encodeDER seqAst

  AuthorityInfoAccess accessList ->
    let
      descAsts = accessList <#> \{ accessMethod: OID arcs, accessLocation } ->
        let
          methodAst = ASN1 (makeUniversalTag 6 Primitive) (ASN1OID arcs)
          locAst = encodeGeneralNameAst accessLocation
        in
          ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [ methodAst, locAst ])
      seqAst = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence descAsts)
    in
      encodeDER seqAst

  CrlDistributionPoints points ->
    let
      distPointAsts = points <#> \pt ->
        let
          locAst = encodeGeneralNameAst pt
          genNamesAst = ASN1 (ASN1Tag { tagClass: ContextSpecific, tagForm: Constructed, tagNumber: 0 })
            (ASN1Sequence [ locAst ])
          distPointNameAst = ASN1 (ASN1Tag { tagClass: ContextSpecific, tagForm: Constructed, tagNumber: 0 })
            (ASN1Sequence [ genNamesAst ])
        in
          ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [ distPointNameAst ])
      seqAst = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence distPointAsts)
    in
      encodeDER seqAst

  NameConstraints { permittedSubtrees, excludedSubtrees } ->
    let
      permAst = if length permittedSubtrees == 0 then []
                else [ ASN1 (ASN1Tag { tagClass: ContextSpecific, tagForm: Constructed, tagNumber: 0 })
                         (ASN1Sequence (permittedSubtrees <#> encodeSubtreeAst)) ]
      exclAst = if length excludedSubtrees == 0 then []
                else [ ASN1 (ASN1Tag { tagClass: ContextSpecific, tagForm: Constructed, tagNumber: 1 })
                         (ASN1Sequence (excludedSubtrees <#> encodeSubtreeAst)) ]
      seqAst = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence (permAst <> exclAst))
    in
      encodeDER seqAst

  CertificatePolicies policies ->
    let
      polAsts = policies <#> \(OID arcs) ->
        let oidAst = ASN1 (makeUniversalTag 6 Primitive) (ASN1OID arcs)
        in ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [ oidAst ])
      seqAst = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence polAsts)
    in
      encodeDER seqAst

  PrecertificatePoison ->
    encodeDER (ASN1 (makeUniversalTag 5 Primitive) ASN1Null)

  EmbeddedSctList bytes -> bytes
  RawExtension bytes -> bytes
  where
  flagBit = case _ of
    DigitalSignature -> 0x80
    NonRepudiation -> 0x40
    KeyEncipherment -> 0x20
    DataEncipherment -> 0x10
    KeyAgreement -> 0x08
    KeyCertSign -> 0x04
    CRLSign -> 0x02
    EncipherOnly -> 0x01
    DecipherOnly -> 0x00

  flagBitHigh = case _ of
    DecipherOnly -> 0x80
    _ -> 0x00

encodeGeneralNameAst :: GeneralName -> ASN1
encodeGeneralNameAst = case _ of
  DnsName dns ->
    ASN1 (ASN1Tag { tagClass: ContextSpecific, tagForm: Primitive, tagNumber: 2 })
      (ASN1ContextImplicit 2 (stringToBytes dns))
  IpAddress ip ->
    ASN1 (ASN1Tag { tagClass: ContextSpecific, tagForm: Primitive, tagNumber: 7 })
      (ASN1ContextImplicit 7 ip)
  Rfc822Name email ->
    ASN1 (ASN1Tag { tagClass: ContextSpecific, tagForm: Primitive, tagNumber: 1 })
      (ASN1ContextImplicit 1 (stringToBytes email))
  Uri uri ->
    ASN1 (ASN1Tag { tagClass: ContextSpecific, tagForm: Primitive, tagNumber: 6 })
      (ASN1ContextImplicit 6 (stringToBytes uri))
  where
  stringToBytes s = toCharArray s <#> \c -> charCode c .&. 0xff
  charCode c = case c of
    'a' -> 97
    'b' -> 98
    'c' -> 99
    'd' -> 100
    'e' -> 101
    'f' -> 102
    'g' -> 103
    'h' -> 104
    'i' -> 105
    'j' -> 106
    'k' -> 107
    'l' -> 108
    'm' -> 109
    'n' -> 110
    'o' -> 111
    'p' -> 112
    'q' -> 113
    'r' -> 114
    's' -> 115
    't' -> 116
    'u' -> 117
    'v' -> 118
    'w' -> 119
    'x' -> 120
    'y' -> 121
    'z' -> 122
    'A' -> 65
    'B' -> 66
    'C' -> 67
    'D' -> 68
    'E' -> 69
    'F' -> 70
    'G' -> 71
    'H' -> 72
    'I' -> 73
    'J' -> 74
    'K' -> 75
    'L' -> 76
    'M' -> 77
    'N' -> 78
    'O' -> 79
    'P' -> 80
    'Q' -> 81
    'R' -> 82
    'S' -> 83
    'T' -> 84
    'U' -> 85
    'V' -> 86
    'W' -> 87
    'X' -> 88
    'Y' -> 89
    'Z' -> 90
    '0' -> 48
    '1' -> 49
    '2' -> 50
    '3' -> 51
    '4' -> 52
    '5' -> 53
    '6' -> 54
    '7' -> 55
    '8' -> 56
    '9' -> 57
    '.' -> 46
    '-' -> 45
    '_' -> 95
    ':' -> 58
    '/' -> 47
    '@' -> 64
    _ -> 63

encodeSubtreeAst :: GeneralSubtree -> ASN1
encodeSubtreeAst (GeneralSubtree { base, minimum, maximum }) =
  let
    baseAst = encodeGeneralNameAst base
    minAst = if minimum == 0 then []
             else [ ASN1 (ASN1Tag { tagClass: ContextSpecific, tagForm: Primitive, tagNumber: 0 })
                      (ASN1ContextImplicit 0 [ minimum ]) ]
    maxAst = case maximum of
      Just m -> [ ASN1 (ASN1Tag { tagClass: ContextSpecific, tagForm: Primitive, tagNumber: 1 })
                    (ASN1ContextImplicit 1 [ m ]) ]
      Nothing -> []
  in
    ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence ([ baseAst ] <> minAst <> maxAst))

-- | Decodes an Extension ASN.1 Sequence into an Extension record.
decodeExtensionAst :: ASN1 -> Maybe Extension
decodeExtensionAst (ASN1 _ (ASN1Sequence elements)) =
  case elements of
    [ ASN1 _ (ASN1OID arcs), ASN1 _ (ASN1Boolean crit), ASN1 _ (ASN1OctetString payload) ] ->
      let oid = OID arcs
          val = decodeExtensionValue oid payload
      in Just { oid, critical: crit, value: val }
    [ ASN1 _ (ASN1OID arcs), ASN1 _ (ASN1OctetString payload) ] ->
      let oid = OID arcs
          val = decodeExtensionValue oid payload
      in Just { oid, critical: false, value: val }
    _ -> Nothing
decodeExtensionAst _ = Nothing

-- | Decodes raw extension octets based on known OIDs.
decodeExtensionValue :: OID -> Array Int -> ExtensionValue
decodeExtensionValue targetOid payload
  | targetOid == extBasicConstraints =
      case decodeDER payload of
        Just { element: ASN1 _ (ASN1Sequence elems) } ->
          let
            mCA = case uncons elems of
              Just { head: ASN1 _ (ASN1Boolean b) } -> b
              _ -> false
            mPathLen = foldl (\acc el ->
              case acc, el of
                Just _, _ -> acc
                Nothing, ASN1 _ (ASN1Integer bi) -> BigInt.toString bi # fromString
                _, _ -> Nothing
            ) Nothing elems
          in
            BasicConstraints { isCA: mCA, pathLenConstraint: mPathLen }
        _ -> BasicConstraints { isCA: false, pathLenConstraint: Nothing }

  | targetOid == extKeyUsage =
      case decodeDER payload of
        Just { element: ASN1 _ (ASN1BitString _ bytes) } ->
          let
            b0 = fromMaybe 0 (bytes !! 0)
            b1 = fromMaybe 0 (bytes !! 1)
            f0 = if (b0 .&. 0x80) /= 0 then [ DigitalSignature ] else []
            f1 = if (b0 .&. 0x40) /= 0 then [ NonRepudiation ] else []
            f2 = if (b0 .&. 0x20) /= 0 then [ KeyEncipherment ] else []
            f3 = if (b0 .&. 0x10) /= 0 then [ DataEncipherment ] else []
            f4 = if (b0 .&. 0x08) /= 0 then [ KeyAgreement ] else []
            f5 = if (b0 .&. 0x04) /= 0 then [ KeyCertSign ] else []
            f6 = if (b0 .&. 0x02) /= 0 then [ CRLSign ] else []
            f7 = if (b0 .&. 0x01) /= 0 then [ EncipherOnly ] else []
            f8 = if (b1 .&. 0x80) /= 0 then [ DecipherOnly ] else []
          in
            KeyUsage (f0 <> f1 <> f2 <> f3 <> f4 <> f5 <> f6 <> f7 <> f8)
        _ -> KeyUsage []

  | targetOid == extExtKeyUsage =
      case decodeDER payload of
        Just { element: ASN1 _ (ASN1Sequence elems) } ->
          let oids = foldl (\acc el ->
                case el of
                  ASN1 _ (ASN1OID arcs) -> acc <> [ OID arcs ]
                  _ -> acc
              ) [] elems
          in ExtKeyUsage oids
        _ -> ExtKeyUsage []

  | targetOid == extSubjectAltName || targetOid == extIssuerAltName =
      case decodeDER payload of
        Just { element: ASN1 _ (ASN1Sequence elems) } ->
          let names = foldl (\acc el ->
                case decodeGeneralName el of
                  Just gn -> acc <> [ gn ]
                  Nothing -> acc
              ) [] elems
          in if targetOid == extSubjectAltName then SubjectAltName names else IssuerAltName names
        _ -> if targetOid == extSubjectAltName then SubjectAltName [] else IssuerAltName []

  | targetOid == extSubjectKeyIdentifier =
      case decodeDER payload of
        Just { element: ASN1 _ (ASN1OctetString kid) } -> SubjectKeyIdentifier kid
        _ -> SubjectKeyIdentifier payload

  | targetOid == extAuthorityKeyIdentifier =
      case decodeDER payload of
        Just { element: ASN1 _ (ASN1Sequence elems) } ->
          let
            mKid = foldl (\acc el ->
              case acc, el of
                Just _, _ -> acc
                Nothing, ASN1 (ASN1Tag { tagNumber: 0 }) (ASN1ContextImplicit _ bytes) -> Just bytes
                Nothing, ASN1 (ASN1Tag { tagNumber: 0 }) (ASN1OctetString bytes) -> Just bytes
                _, _ -> Nothing
            ) Nothing elems
            mSerial = foldl (\acc el ->
              case acc, el of
                Just _, _ -> acc
                Nothing, ASN1 (ASN1Tag { tagNumber: 2 }) (ASN1ContextImplicit _ bytes) -> Just (decodeIntegerDER bytes)
                Nothing, ASN1 (ASN1Tag { tagNumber: 2 }) (ASN1Integer bi) -> Just bi
                _, _ -> Nothing
            ) Nothing elems
          in
            AuthorityKeyIdentifier { keyIdentifier: mKid, authorityCertSerialNumber: mSerial }
        _ -> AuthorityKeyIdentifier { keyIdentifier: Nothing, authorityCertSerialNumber: Nothing }

  | targetOid == extPrecertPoison = PrecertificatePoison
  | targetOid == extEmbeddedSctList = EmbeddedSctList payload
  | otherwise = RawExtension payload

decodeGeneralName :: ASN1 -> Maybe GeneralName
decodeGeneralName (ASN1 (ASN1Tag { tagClass: ContextSpecific, tagNumber }) val) =
  case tagNumber of
    2 -> -- DNS
      case val of
        ASN1ContextImplicit _ bytes -> Just (DnsName (bytesToString bytes))
        ASN1IA5String s -> Just (DnsName s)
        _ -> Nothing
    7 -> -- IP
      case val of
        ASN1ContextImplicit _ bytes -> Just (IpAddress bytes)
        ASN1OctetString bytes -> Just (IpAddress bytes)
        _ -> Nothing
    1 -> -- RFC822 / Email
      case val of
        ASN1ContextImplicit _ bytes -> Just (Rfc822Name (bytesToString bytes))
        ASN1IA5String s -> Just (Rfc822Name s)
        _ -> Nothing
    6 -> -- URI
      case val of
        ASN1ContextImplicit _ bytes -> Just (Uri (bytesToString bytes))
        ASN1IA5String s -> Just (Uri s)
        _ -> Nothing
    _ -> Nothing
  where
  bytesToString bs = fromCharArray (bs <#> \b -> asciiChar (b .&. 0x7f))
  asciiChar b = case b of
    48 -> '0'
    49 -> '1'
    50 -> '2'
    51 -> '3'
    52 -> '4'
    53 -> '5'
    54 -> '6'
    55 -> '7'
    56 -> '8'
    57 -> '9'
    97 -> 'a'
    98 -> 'b'
    99 -> 'c'
    100 -> 'd'
    101 -> 'e'
    102 -> 'f'
    103 -> 'g'
    104 -> 'h'
    105 -> 'i'
    106 -> 'j'
    107 -> 'k'
    108 -> 'l'
    109 -> 'm'
    110 -> 'n'
    111 -> 'o'
    112 -> 'p'
    113 -> 'q'
    114 -> 'r'
    115 -> 's'
    116 -> 't'
    117 -> 'u'
    118 -> 'v'
    119 -> 'w'
    120 -> 'x'
    121 -> 'y'
    122 -> 'z'
    65 -> 'A'
    66 -> 'B'
    67 -> 'C'
    68 -> 'D'
    69 -> 'E'
    70 -> 'F'
    71 -> 'G'
    72 -> 'H'
    73 -> 'I'
    74 -> 'J'
    75 -> 'K'
    76 -> 'L'
    77 -> 'M'
    78 -> 'N'
    79 -> 'O'
    80 -> 'P'
    81 -> 'Q'
    82 -> 'R'
    83 -> 'S'
    84 -> 'T'
    85 -> 'U'
    86 -> 'V'
    87 -> 'W'
    88 -> 'X'
    89 -> 'Y'
    90 -> 'Z'
    32 -> ' '
    46 -> '.'
    58 -> ':'
    47 -> '/'
    45 -> '-'
    95 -> '_'
    64 -> '@'
    _ -> '?'
decodeGeneralName _ = Nothing

-- | Finds an extension by OID in an array of extensions.
findExtension :: OID -> Array Extension -> Maybe Extension
findExtension targetOid exts =
  foldl (\acc ext ->
    case acc of
      Just _ -> acc
      Nothing -> if ext.oid == targetOid then Just ext else Nothing
  ) Nothing exts

-- | Checks if an array of extensions grants a specific KeyUsage flag.
hasKeyUsage :: KeyUsageFlag -> Array Extension -> Boolean
hasKeyUsage flag exts =
  case findExtension extKeyUsage exts of
    Just { value: KeyUsage flags } ->
      foldl (\acc f -> acc || f == flag) false flags
    _ -> false

-- | Extracts all SAN DNS names from an array of extensions.
getSanDnsNames :: Array Extension -> Array String
getSanDnsNames exts =
  case findExtension extSubjectAltName exts of
    Just { value: SubjectAltName names } ->
      foldl (\acc gn ->
        case gn of
          DnsName s -> acc <> [ s ]
          _ -> acc
      ) [] names
    _ -> []

-- | Extracts all SAN IP addresses from an array of extensions.
getSanIpAddresses :: Array Extension -> Array (Array Int)
getSanIpAddresses exts =
  case findExtension extSubjectAltName exts of
    Just { value: SubjectAltName names } ->
      foldl (\acc gn ->
        case gn of
          IpAddress ip -> acc <> [ ip ]
          _ -> acc
      ) [] names
    _ -> []

-- | Checks if an extension set marks the certificate as a CA (BasicConstraints.isCA == true).
isCaExtension :: Array Extension -> Boolean
isCaExtension exts =
  case findExtension extBasicConstraints exts of
    Just { value: BasicConstraints { isCA } } -> isCA
    _ -> false

-- | Extracts the pathLenConstraint from BasicConstraints if present.
getPathLenConstraint :: Array Extension -> Maybe Int
getPathLenConstraint exts =
  case findExtension extBasicConstraints exts of
    Just { value: BasicConstraints { pathLenConstraint } } -> pathLenConstraint
    _ -> Nothing
