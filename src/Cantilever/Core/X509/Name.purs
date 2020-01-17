module Cantilever.Core.X509.Name
  ( AttributeTypeAndValue(..)
  , RelativeDistinguishedName
  , DistinguishedName(..)
  , commonName
  , organization
  , organizationalUnit
  , country
  , stateOrProvince
  , locality
  , serialNumberAttr
  , formatDN
  , parseDN
  , getCommonName
  , getOrganization
  , getCountry
  , encodeDNAst
  , decodeDNAst
  , canonicalDNCompare
  ) where

import Prelude

import Cantilever.Core.ASN1.OID
  ( OID(..)
  , atCommonName
  , atCountryName
  , atLocalityName
  , atOrganizationName
  , atOrganizationalUnitName
  , atSerialNumber
  , atStateOrProvinceName
  )
import Cantilever.Core.ASN1.Types (ASN1(..), ASN1Value(..), TagForm(..), makeUniversalTag)
import Data.Array (foldl, uncons)
import Data.Maybe (Maybe(..))
import Data.String.Common (split, toLower, trim)
import Data.String.Pattern (Pattern(..))

-- | Individual attribute type and value in an X.500 Name.
data AttributeTypeAndValue = AttributeTypeAndValue OID String

derive instance eqAttributeTypeAndValue :: Eq AttributeTypeAndValue
derive instance ordAttributeTypeAndValue :: Ord AttributeTypeAndValue

instance showAttributeTypeAndValue :: Show AttributeTypeAndValue where
  show (AttributeTypeAndValue oid val) =
    shortOidName oid <> "=" <> val
    where
    shortOidName o
      | o == atCommonName = "CN"
      | o == atOrganizationName = "O"
      | o == atOrganizationalUnitName = "OU"
      | o == atCountryName = "C"
      | o == atStateOrProvinceName = "ST"
      | o == atLocalityName = "L"
      | o == atSerialNumber = "serialNumber"
      | otherwise = show o

-- | A Relative Distinguished Name (RDN) is a set of attributes (usually single-valued).
type RelativeDistinguishedName = Array AttributeTypeAndValue

-- | An X.500 Distinguished Name (DN) represented as a sequence of RDNs.
newtype DistinguishedName = DistinguishedName (Array RelativeDistinguishedName)

derive instance eqDistinguishedName :: Eq DistinguishedName
derive instance ordDistinguishedName :: Ord DistinguishedName

instance showDistinguishedName :: Show DistinguishedName where
  show = formatDN

commonName :: String -> RelativeDistinguishedName
commonName cn = [ AttributeTypeAndValue atCommonName cn ]

organization :: String -> RelativeDistinguishedName
organization org = [ AttributeTypeAndValue atOrganizationName org ]

organizationalUnit :: String -> RelativeDistinguishedName
organizationalUnit ou = [ AttributeTypeAndValue atOrganizationalUnitName ou ]

country :: String -> RelativeDistinguishedName
country c = [ AttributeTypeAndValue atCountryName c ]

stateOrProvince :: String -> RelativeDistinguishedName
stateOrProvince st = [ AttributeTypeAndValue atStateOrProvinceName st ]

locality :: String -> RelativeDistinguishedName
locality l = [ AttributeTypeAndValue atLocalityName l ]

serialNumberAttr :: String -> RelativeDistinguishedName
serialNumberAttr sn = [ AttributeTypeAndValue atSerialNumber sn ]

-- | Formats a Distinguished Name as an RFC 4514 string: "CN=Alice, O=Acme, C=US".
formatDN :: DistinguishedName -> String
formatDN (DistinguishedName rdns) =
  case uncons rdns of
    Nothing -> ""
    Just { head, tail } ->
      foldl (\acc rdn -> acc <> ", " <> formatRdn rdn) (formatRdn head) tail
  where
  formatRdn rdn =
    case uncons rdn of
      Nothing -> ""
      Just { head, tail } ->
        foldl (\acc atv -> acc <> "+" <> show atv) (show head) tail

-- | Parses an RFC 4514 Distinguished Name string: "CN=Alice, O=Acme, C=US".
parseDN :: String -> Maybe DistinguishedName
parseDN str =
  let
    parts = split (Pattern ",") str
    mRdns = sequenceList (parts <#> parseRdnToken)
  in
    mRdns <#> DistinguishedName
  where
  parseRdnToken token =
    let
      clean = trim token
      kv = split (Pattern "=") clean
    in
      case kv of
        [ k, v ] ->
          let
            cleanKey = trim (toLower k)
            cleanVal = trim v
            mOid = case cleanKey of
              "cn" -> Just atCommonName
              "commonname" -> Just atCommonName
              "o" -> Just atOrganizationName
              "organization" -> Just atOrganizationName
              "ou" -> Just atOrganizationalUnitName
              "c" -> Just atCountryName
              "st" -> Just atStateOrProvinceName
              "l" -> Just atLocalityName
              "serialnumber" -> Just atSerialNumber
              _ -> Nothing
          in
            mOid <#> \oid -> [ AttributeTypeAndValue oid cleanVal ]
        _ -> Nothing

getCommonName :: DistinguishedName -> Maybe String
getCommonName (DistinguishedName rdns) = findAttr atCommonName rdns

getOrganization :: DistinguishedName -> Maybe String
getOrganization (DistinguishedName rdns) = findAttr atOrganizationName rdns

getCountry :: DistinguishedName -> Maybe String
getCountry (DistinguishedName rdns) = findAttr atCountryName rdns

findAttr :: OID -> Array RelativeDistinguishedName -> Maybe String
findAttr targetOid rdns =
  foldl (\acc rdn ->
    case acc of
      Just _ -> acc
      Nothing ->
        foldl (\inner (AttributeTypeAndValue o val) ->
          if o == targetOid then Just val else inner
        ) Nothing rdn
  ) Nothing rdns

-- | Encodes a Distinguished Name into an ASN.1 RDNSequence.
encodeDNAst :: DistinguishedName -> ASN1
encodeDNAst (DistinguishedName rdns) =
  let
    seqTag = makeUniversalTag 16 Constructed
    setTag = makeUniversalTag 17 Constructed
    atvSeqTag = makeUniversalTag 16 Constructed

    rdnAsts = rdns <#> \rdn ->
      let
        atvAsts = rdn <#> \(AttributeTypeAndValue (OID arcs) val) ->
          let
            oidAst = ASN1 (makeUniversalTag 6 Primitive) (ASN1OID arcs)
            valAst = ASN1 (makeUniversalTag 12 Primitive) (ASN1UTF8String val)
          in
            ASN1 atvSeqTag (ASN1Sequence [ oidAst, valAst ])
      in
        ASN1 setTag (ASN1Set atvAsts)
  in
    ASN1 seqTag (ASN1Sequence rdnAsts)

-- | Decodes an ASN.1 RDNSequence into a typed Distinguished Name.
decodeDNAst :: ASN1 -> Maybe DistinguishedName
decodeDNAst (ASN1 _ (ASN1Sequence rdnElements)) =
  let
    mRdns = sequenceList (rdnElements <#> decodeRdnSet)
  in
    mRdns <#> DistinguishedName
  where
  decodeRdnSet (ASN1 _ (ASN1Set atvElements)) =
    sequenceList (atvElements <#> decodeAtvSeq)
  decodeRdnSet (ASN1 _ (ASN1Sequence atvElements)) =
    sequenceList (atvElements <#> decodeAtvSeq)
  decodeRdnSet _ = Nothing

  decodeAtvSeq (ASN1 _ (ASN1Sequence [ ASN1 _ (ASN1OID arcs), valAst ])) =
    let strVal = extractString valAst
    in Just (AttributeTypeAndValue (OID arcs) strVal)
  decodeAtvSeq _ = Nothing

  extractString (ASN1 _ val) = case val of
    ASN1UTF8String s -> s
    ASN1PrintableString s -> s
    ASN1IA5String s -> s
    _ -> ""
decodeDNAst _ = Nothing

sequenceList :: forall a. Array (Maybe a) -> Maybe (Array a)
sequenceList = foldl (\acc mx ->
  case acc, mx of
    Just xs, Just x -> Just (xs <> [ x ])
    _, _ -> Nothing
) (Just [])

-- | Canonical comparison of two DNs according to RFC 5280 Section 7.1.
canonicalDNCompare :: DistinguishedName -> DistinguishedName -> Boolean
canonicalDNCompare dnA dnB =
  normalizeDN dnA == normalizeDN dnB
  where
  normalizeDN (DistinguishedName rdns) =
    rdns <#> \rdn ->
      rdn <#> \(AttributeTypeAndValue o v) ->
        AttributeTypeAndValue o (trim (toLower v))
