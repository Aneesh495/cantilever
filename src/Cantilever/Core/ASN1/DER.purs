module Cantilever.Core.ASN1.DER
  ( encodeDER
  , decodeDER
  , decodeDERMany
  , encodeIntegerDER
  , decodeIntegerDER
  , encodeLengthDER
  , decodeLengthDER
  , encodeTagDER
  , decodeTagDER
  ) where

import Prelude

import Cantilever.Core.ASN1.OID (OID(..), decodeOIDDer, encodeOIDDer)
import Cantilever.Core.ASN1.Types
  ( ASN1(..)
  , ASN1Tag(..)
  , ASN1Value(..)
  , TagClass(..)
  , TagForm(..)
  )
import Cantilever.Core.Crypto.BigInt (BigInt, fromOctets, toOctets)
import Cantilever.Core.Crypto.BigInt as BigInt
import Data.Array ((..), (!!), cons, drop, foldl, length, sortBy, take, uncons)
import Data.Int.Bits ((.&.), (.|.), shl, zshr)
import Data.Maybe (Maybe(..), fromMaybe)
import Data.String.CodeUnits (fromCharArray, toCharArray)

-- | Encodes an ASN1 element into Distinguished Encoding Rules (DER) octets.
encodeDER :: ASN1 -> Array Int
encodeDER (ASN1 tag val) =
  let
    payload = encodeValueDER val
    tagOctets = encodeTagDER tag
    lenOctets = encodeLengthDER (length payload)
  in
    tagOctets <> lenOctets <> payload

encodeValueDER :: ASN1Value -> Array Int
encodeValueDER = case _ of
  ASN1Boolean b -> [ if b then 0xff else 0x00 ]
  ASN1Integer bi -> encodeIntegerDER bi
  ASN1BitString unused bytes -> cons (unused .&. 0x07) bytes
  ASN1OctetString bytes -> bytes
  ASN1Null -> []
  ASN1OID oidArcs -> encodeOIDDer (OID oidArcs)
  ASN1UTF8String s -> stringToUtf8Bytes s
  ASN1PrintableString s -> stringToAsciiBytes s
  ASN1IA5String s -> stringToAsciiBytes s
  ASN1UTCTime s -> stringToAsciiBytes s
  ASN1GeneralizedTime s -> stringToAsciiBytes s
  ASN1Sequence children -> foldl (\acc child -> acc <> encodeDER child) [] children
  ASN1Set children ->
    -- Strict DER requires Set elements to be canonically ordered by their encoded DER bytes.
    let
      encodedChildren = children <#> \child ->
        { original: child, bytes: encodeDER child }
      sorted = sortBy (\a b -> compareBytes a.bytes b.bytes) encodedChildren
    in
      foldl (\acc item -> acc <> item.bytes) [] sorted
  ASN1ContextExplicit _ inner -> encodeDER inner
  ASN1ContextImplicit _ bytes -> bytes
  ASN1Raw bytes -> bytes

-- | Lexicographical byte comparison for canonical DER Set sorting.
compareBytes :: Array Int -> Array Int -> Ordering
compareBytes a b =
  case uncons a, uncons b of
    Nothing, Nothing -> EQ
    Nothing, Just _ -> LT
    Just _, Nothing -> GT
    Just { head: h1, tail: t1 }, Just { head: h2, tail: t2 } ->
      if h1 < h2 then LT
      else if h1 > h2 then GT
      else compareBytes t1 t2

-- | Encodes an arbitrary-precision integer into two's complement DER bytes.
encodeIntegerDER :: BigInt -> Array Int
encodeIntegerDER bi =
  if bi == BigInt.bigZero then
    [ 0x00 ]
  else
    let
      rawOctets = toOctets bi
      firstByte = fromMaybe 0 (rawOctets !! 0)
    in
      -- If highest bit is set on positive integer, prepend 0x00 to prevent sign confusion.
      if (firstByte .&. 0x80) /= 0 then
        cons 0x00 rawOctets
      else
        rawOctets

-- | Decodes two's complement DER bytes into BigInt.
decodeIntegerDER :: Array Int -> BigInt
decodeIntegerDER bytes =
  case uncons bytes of
    Nothing -> BigInt.bigZero
    Just _ -> fromOctets bytes

-- | Encodes length according to DER definite form.
encodeLengthDER :: Int -> Array Int
encodeLengthDER len
  | len < 128 = [ len ]
  | len < 256 = [ 0x81, len ]
  | len < 65536 = [ 0x82, zshr len 8, len .&. 0xff ]
  | len < 16777216 = [ 0x83, zshr len 16, (zshr len 8) .&. 0xff, len .&. 0xff ]
  | otherwise = [ 0x84, zshr len 24, (zshr len 16) .&. 0xff, (zshr len 8) .&. 0xff, len .&. 0xff ]

-- | Decodes definite DER length. Rejects indefinite length (0x80).
decodeLengthDER :: Array Int -> Maybe { length :: Int, consumed :: Int }
decodeLengthDER bytes =
  case uncons bytes of
    Nothing -> Nothing
    Just { head: b0, tail: rest } ->
      if (b0 .&. 0x80) == 0 then
        -- Short form: length is direct value (0..127)
        Just { length: b0, consumed: 1 }
      else
        let numOctets = b0 .&. 0x7f
        in
          if numOctets == 0 then
            -- 0x80 represents indefinite length, which is strictly forbidden in DER
            Nothing
          else if numOctets > 4 || length rest < numOctets then
            Nothing
          else
            let
              lenBytes = take numOctets rest
              val = foldl (\acc b -> (shl acc 8) .|. (b .&. 0xff)) 0 lenBytes
            in
              -- Strict DER: non-minimal encodings (e.g. 0x81 0x7F) are invalid
              if numOctets == 1 && val < 128 then Nothing
              else Just { length: val, consumed: 1 + numOctets }

-- | Encodes an ASN1Tag into DER octets.
encodeTagDER :: ASN1Tag -> Array Int
encodeTagDER (ASN1Tag { tagClass, tagForm, tagNumber }) =
  let
    classBits = case tagClass of
      Universal -> 0x00
      Application -> 0x40
      ContextSpecific -> 0x80
      Private -> 0xc0
    formBits = case tagForm of
      Primitive -> 0x00
      Constructed -> 0x20
  in
    if tagNumber < 31 then
      [ classBits .|. formBits .|. (tagNumber .&. 0x1f) ]
    else
      let
        firstOctet = classBits .|. formBits .|. 0x1f
        vlqOctets = encodeTagNumberVlq tagNumber
      in
        cons firstOctet vlqOctets
  where
  encodeTagNumberVlq num =
    let raw = go [] num
    in markLast raw
    where
    go acc n =
      if n == 0 then (if length acc == 0 then [ 0 ] else acc)
      else go (cons (n .&. 0x7f) acc) (zshr n 7)

    markLast arr =
      let n = length arr
      in (0 .. (n - 1)) <#> \i ->
        let b = fromMaybe 0 (arr !! i)
        in if i == n - 1 then b else b .|. 0x80

-- | Decodes ASN1Tag from octets.
decodeTagDER :: Array Int -> Maybe { tag :: ASN1Tag, consumed :: Int }
decodeTagDER bytes =
  case uncons bytes of
    Nothing -> Nothing
    Just { head: b0, tail: rest } ->
      let
        tagClass = case zshr b0 6 of
          0 -> Universal
          1 -> Application
          2 -> ContextSpecific
          _ -> Private
        tagForm = if (b0 .&. 0x20) /= 0 then Constructed else Primitive
        tagNumLow = b0 .&. 0x1f
      in
        if tagNumLow < 31 then
          Just { tag: ASN1Tag { tagClass, tagForm, tagNumber: tagNumLow }, consumed: 1 }
        else
          decodeMultiOctetTag tagClass tagForm [] rest
  where
  decodeMultiOctetTag tc tf acc remBytes =
    case uncons remBytes of
      Nothing -> Nothing
      Just { head: b, tail: xs } ->
        let
          num = (b .&. 0x7f)
          newAcc = acc <> [ num ]
          isLast = (b .&. 0x80) == 0
        in
          if isLast then
            let finalTagNum = foldl (\a x -> (shl a 7) .|. x) 0 newAcc
            in Just { tag: ASN1Tag { tagClass: tc, tagForm: tf, tagNumber: finalTagNum }, consumed: 1 + length newAcc }
          else
            decodeMultiOctetTag tc tf newAcc xs

-- | Decodes a single ASN.1 element from DER octets.
decodeDER :: Array Int -> Maybe { element :: ASN1, consumed :: Int }
decodeDER bytes = do
  { tag, consumed: tagConsumed } <- decodeTagDER bytes
  let afterTag = drop tagConsumed bytes
  { length: payloadLen, consumed: lenConsumed } <- decodeLengthDER afterTag
  let
    headerConsumed = tagConsumed + lenConsumed
    afterHeader = drop lenConsumed afterTag
  if length afterHeader < payloadLen then
    Nothing
  else
    let
      payloadBytes = take payloadLen afterHeader
      totalConsumed = headerConsumed + payloadLen
      value = decodeValueDER tag payloadBytes
    in
      Just { element: ASN1 tag value, consumed: totalConsumed }

-- | Decodes multiple consecutive ASN.1 elements from DER octets.
decodeDERMany :: Array Int -> Array ASN1
decodeDERMany bytes = go [] bytes
  where
  go acc remBytes =
    case decodeDER remBytes of
      Nothing -> acc
      Just { element, consumed } ->
        go (acc <> [ element ]) (drop consumed remBytes)

decodeValueDER :: ASN1Tag -> Array Int -> ASN1Value
decodeValueDER (ASN1Tag { tagClass, tagForm, tagNumber }) payload =
  case tagClass of
    Universal -> decodeUniversalValue tagNumber tagForm payload
    ContextSpecific ->
      case tagForm of
        Constructed ->
          case decodeDER payload of
            Just { element } -> ASN1ContextExplicit tagNumber element
            Nothing -> ASN1ContextImplicit tagNumber payload
        Primitive ->
          ASN1ContextImplicit tagNumber payload
    _ -> ASN1Raw payload

decodeUniversalValue :: Int -> TagForm -> Array Int -> ASN1Value
decodeUniversalValue tagNum form payload =
  case tagNum of
    1 ->
      let b = fromMaybe 0 (payload !! 0)
      in ASN1Boolean (b /= 0)
    2 ->
      ASN1Integer (decodeIntegerDER payload)
    3 ->
      case uncons payload of
        Just { head: unused, tail: bits } -> ASN1BitString unused bits
        Nothing -> ASN1BitString 0 []
    4 ->
      ASN1OctetString payload
    5 ->
      ASN1Null
    6 ->
      case decodeOIDDer payload of
        Just (OID arcs) -> ASN1OID arcs
        Nothing -> ASN1Raw payload
    12 ->
      ASN1UTF8String (bytesToUtf8String payload)
    16 ->
      ASN1Sequence (decodeDERMany payload)
    17 ->
      ASN1Set (decodeDERMany payload)
    19 ->
      ASN1PrintableString (bytesToAsciiString payload)
    22 ->
      ASN1IA5String (bytesToAsciiString payload)
    23 ->
      ASN1UTCTime (bytesToAsciiString payload)
    24 ->
      ASN1GeneralizedTime (bytesToAsciiString payload)
    _ ->
      case form of
        Constructed -> ASN1Sequence (decodeDERMany payload)
        Primitive -> ASN1Raw payload

stringToAsciiBytes :: String -> Array Int
stringToAsciiBytes s = toCharArray s <#> \c -> charCode c .&. 0xff
  where
  charCode c = case c of
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
    ' ' -> 32
    '.' -> 46
    ':' -> 58
    '/' -> 47
    '-' -> 45
    '_' -> 95
    '@' -> 64
    '=' -> 61
    ',' -> 44
    _ -> 63

bytesToAsciiString :: Array Int -> String
bytesToAsciiString bytes =
  fromCharArray (bytes <#> \b -> asciiChar (b .&. 0x7f))
  where
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
    61 -> '='
    44 -> ','
    _ -> '?'

stringToUtf8Bytes :: String -> Array Int
stringToUtf8Bytes s = stringToAsciiBytes s

bytesToUtf8String :: Array Int -> String
bytesToUtf8String bytes = bytesToAsciiString bytes
