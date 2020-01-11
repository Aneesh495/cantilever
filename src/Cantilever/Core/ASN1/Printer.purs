module Cantilever.Core.ASN1.Printer
  ( printASN1Tree
  , printASN1Value
  ) where

import Prelude

import Cantilever.Core.ASN1.OID (OID(..), oidName)
import Cantilever.Core.ASN1.Types (ASN1(..), ASN1Tag(..), ASN1Value(..), TagClass(..))
import Cantilever.Core.Crypto.BigInt (toString)
import Cantilever.Core.Crypto.Hash (toHex)
import Data.Array (foldl, length, replicate, take)
import Data.String.CodeUnits (fromCharArray)

-- | Pretty-prints an ASN.1 element as an indented diagnostic tree.
printASN1Tree :: ASN1 -> String
printASN1Tree = formatNode 0

formatNode :: Int -> ASN1 -> String
formatNode depth (ASN1 (ASN1Tag { tagClass, tagForm: _, tagNumber }) val) =
  let
    indent = indentString depth
    header = indent <> tagDescription tagClass tagNumber <> ": "
  in
    case val of
      ASN1Sequence children ->
        header <> "Sequence (" <> show (length children) <> " elements)\n" <>
          foldl (\acc c -> acc <> formatNode (depth + 1) c) "" children
      ASN1Set children ->
        header <> "Set (" <> show (length children) <> " elements)\n" <>
          foldl (\acc c -> acc <> formatNode (depth + 1) c) "" children
      ASN1ContextExplicit n inner ->
        header <> "[" <> show n <> "] (Explicit)\n" <> formatNode (depth + 1) inner
      _ ->
        header <> printASN1Value val <> "\n"

indentString :: Int -> String
indentString depth =
  fromCharArray (replicate (depth * 2) ' ')

tagDescription :: TagClass -> Int -> String
tagDescription tc num =
  case tc of
    Universal -> universalTagName num
    ContextSpecific -> "[" <> show num <> "]"
    Application -> "Application[" <> show num <> "]"
    Private -> "Private[" <> show num <> "]"
  where
  universalTagName = case _ of
    1 -> "BOOLEAN"
    2 -> "INTEGER"
    3 -> "BIT STRING"
    4 -> "OCTET STRING"
    5 -> "NULL"
    6 -> "OBJECT IDENTIFIER"
    12 -> "UTF8String"
    16 -> "SEQUENCE"
    17 -> "SET"
    19 -> "PrintableString"
    22 -> "IA5String"
    23 -> "UTCTime"
    24 -> "GeneralizedTime"
    n -> "Universal[" <> show n <> "]"

-- | Formats an individual ASN.1 value for diagnostic printing.
printASN1Value :: ASN1Value -> String
printASN1Value = case _ of
  ASN1Boolean b -> if b then "TRUE" else "FALSE"
  ASN1Integer bi -> toString bi
  ASN1BitString unused bytes ->
    "unused=" <> show unused <> " bits, hex=" <> takeHex 16 bytes
  ASN1OctetString bytes ->
    "len=" <> show (length bytes) <> ", hex=" <> takeHex 16 bytes
  ASN1Null -> "NULL"
  ASN1OID arcs ->
    let oid = OID arcs
    in oidName oid <> " (" <> show oid <> ")"
  ASN1UTF8String s -> "\"" <> s <> "\""
  ASN1PrintableString s -> "\"" <> s <> "\""
  ASN1IA5String s -> "\"" <> s <> "\""
  ASN1UTCTime s -> s
  ASN1GeneralizedTime s -> s
  ASN1Sequence children -> "Sequence[" <> show (length children) <> "]"
  ASN1Set children -> "Set[" <> show (length children) <> "]"
  ASN1ContextExplicit n _ -> "ContextExplicit[" <> show n <> "]"
  ASN1ContextImplicit n bytes ->
    "[" <> show n <> "] len=" <> show (length bytes) <> ", hex=" <> takeHex 16 bytes
  ASN1Raw bytes -> "Raw len=" <> show (length bytes) <> ", hex=" <> takeHex 16 bytes
  where
  takeHex n bs =
    let preview = take n bs
        hex = toHex preview
    in if length bs > n then hex <> "..." else hex
