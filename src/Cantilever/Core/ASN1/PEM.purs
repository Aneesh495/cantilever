module Cantilever.Core.ASN1.PEM
  ( PEMBlock
  , encodePEM
  , decodePEM
  , decodePEMMany
  , base64Encode
  , base64Decode
  , formatCertificatePEM
  , formatCsrPEM
  , formatPrivateKeyPEM
  , formatCrlPEM
  ) where

import Prelude

import Data.Array (foldl, length, slice, uncons)
import Data.Maybe (Maybe(..))
import Data.String.CodeUnits (fromCharArray, toCharArray)
import Data.String.Common (split)
import Data.String.Pattern (Pattern(..))

-- | A parsed PEM container block with label and raw binary payload.
type PEMBlock =
  { label :: String
  , bytes :: Array Int
  }

foreign import base64EncodeImpl :: Array Int -> String
foreign import base64DecodeImpl :: (forall a. a -> Maybe a) -> (forall a. Maybe a) -> String -> Maybe (Array Int)

base64Encode :: Array Int -> String
base64Encode = base64EncodeImpl

base64Decode :: String -> Maybe (Array Int)
base64Decode = base64DecodeImpl Just Nothing

-- | Encodes raw DER bytes into a formatted RFC 7468 PEM string with 64-character line wraps.
encodePEM :: String -> Array Int -> String
encodePEM label bytes =
  let
    b64 = base64Encode bytes
    wrapped = foldLines 64 b64
    header = "-----BEGIN " <> label <> "-----\n"
    footer = "-----END " <> label <> "-----\n"
  in
    header <> wrapped <> footer

-- | Folds a base64 string into lines of at most lineWidth characters.
foldLines :: Int -> String -> String
foldLines lineWidth str =
  let
    chars = toCharArray str
    n = length chars
    go i acc =
      if i >= n then acc
      else
        let chunk = fromCharArray (slice i (i + lineWidth) chars)
        in go (i + lineWidth) (acc <> chunk <> "\n")
  in
    go 0 ""

-- | Decodes the first PEM block found in a string.
decodePEM :: String -> Maybe PEMBlock
decodePEM input =
  case decodePEMMany input of
    [ first ] -> Just first
    items ->
      case items of
        [] -> Nothing
        _ ->
          case slice 0 1 items of
            [ x ] -> Just x
            _ -> Nothing

-- | Decodes all PEM blocks from a concatenated PEM string (e.g. certificate chain).
decodePEMMany :: String -> Array PEMBlock
decodePEMMany input =
  let
    lines = split (Pattern "\n") input
  in
    parseLines [] Nothing [] lines
  where
  parseLines blocks mCurrentLabel currentB64 remLines =
    case uncons remLines of
      Nothing -> blocks
      Just { head: line, tail: rest } ->
        let trimmed = stripCarriageReturn line
        in
          if startsWith "-----BEGIN " trimmed then
            let label = extractLabel "-----BEGIN " trimmed
            in parseLines blocks (Just label) [] rest
          else if startsWith "-----END " trimmed then
            case mCurrentLabel of
              Just label ->
                let
                  combinedB64 = foldl (\acc chunk -> acc <> chunk) "" currentB64
                  mBytes = base64Decode combinedB64
                  newBlock = mBytes <#> \bs -> { label, bytes: bs }
                  nextBlocks = case newBlock of
                    Just blk -> blocks <> [ blk ]
                    Nothing -> blocks
                in
                  parseLines nextBlocks Nothing [] rest
              Nothing ->
                parseLines blocks Nothing [] rest
          else
            case mCurrentLabel of
              Just _ ->
                parseLines blocks mCurrentLabel (currentB64 <> [ trimmed ]) rest
              Nothing ->
                parseLines blocks Nothing [] rest

  stripCarriageReturn s =
    let chars = toCharArray s
        n = length chars
    in if n > 0 && slice (n - 1) n chars == [ '\r' ] then
         fromCharArray (slice 0 (n - 1) chars)
       else s

  startsWith pfx s =
    let pChars = toCharArray pfx
        sChars = toCharArray s
        pLen = length pChars
    in length sChars >= pLen && slice 0 pLen sChars == pChars

  extractLabel pfx line =
    let
      pLen = length (toCharArray pfx)
      chars = toCharArray line
      n = length chars
      suffixLen = length (toCharArray "-----")
    in
      if n >= pLen + suffixLen then
        fromCharArray (slice pLen (n - suffixLen) chars)
      else
        ""

formatCertificatePEM :: Array Int -> String
formatCertificatePEM = encodePEM "CERTIFICATE"

formatCsrPEM :: Array Int -> String
formatCsrPEM = encodePEM "CERTIFICATE REQUEST"

formatPrivateKeyPEM :: Array Int -> String
formatPrivateKeyPEM = encodePEM "PRIVATE KEY"

formatCrlPEM :: Array Int -> String
formatCrlPEM = encodePEM "X509 CRL"
