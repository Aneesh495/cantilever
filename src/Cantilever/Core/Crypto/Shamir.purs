module Cantilever.Core.Crypto.Shamir
  ( Share
  , splitSecret
  , combineShares
  , shareToHex
  , shareFromHex
  ) where

import Prelude

import Cantilever.Core.Crypto.Galois (addGF, fromInt, lagrangeBasisGF, mulGF, polyEvalGF, toInt)
import Data.Array ((..), (!!), cons, foldl, length, mapWithIndex, nubBy, uncons)
import Data.Either (Either(..))
import Data.Int (fromStringAs, radix, toStringAs)
import Data.Int.Bits ((.&.))
import Data.Maybe (Maybe(..), fromMaybe)
import Data.String.CodeUnits (fromCharArray, toCharArray)
import Effect (Effect)

foreign import randomBytesImpl :: Int -> Effect (Array Int)

-- | A Shamir secret share consisting of an x-coordinate evaluation point in GF(2^8)
-- | and the evaluated y-coordinate bytes.
type Share =
  { x :: Int
  , y :: Array Int
  }

-- | Splits a secret byte array into n shares with threshold k.
-- | Requires 2 <= k <= n <= 255.
splitSecret :: Int -> Int -> Array Int -> Effect (Either String (Array Share))
splitSecret k n secretBytes
  | k < 2 = pure (Left "Threshold k must be at least 2")
  | n < k = pure (Left "Total shares n must be at least k")
  | n > 255 = pure (Left "Total shares n cannot exceed 255 in GF(2^8)")
  | length secretBytes == 0 = pure (Left "Secret bytes cannot be empty")
  | otherwise = do
      -- For each byte in secret, generate (k - 1) random coefficients.
      let numRand = length secretBytes * (k - 1)
      randBytes <- randomBytesImpl numRand

      let
        shares = (1 .. n) <#> \xVal ->
          let
            xElem = fromInt xVal
            yVals = mapWithIndex (\byteIdx sByte ->
              let
                c0 = fromInt sByte
                randOffset = byteIdx * (k - 1)
                higherCoeffs = (0 .. (k - 2)) <#> \degIdx ->
                  let r = fromMaybe 0 (randBytes !! (randOffset + degIdx))
                  in fromInt r
                coeffs = cons c0 higherCoeffs
                yElem = polyEvalGF coeffs xElem
              in
                toInt yElem
            ) secretBytes
          in
            { x: xVal, y: yVals }

      pure (Right shares)

-- | Combines at least k shares to recover the original secret bytes.
combineShares :: Array Share -> Either String (Array Int)
combineShares shares =
  let
    uniqueShares = nubBy (\a b -> compare a.x b.x) shares
    numShares = length uniqueShares
  in
    if numShares < 2 then
      Left "At least 2 shares are required to combine"
    else
      let
        firstShare = fromMaybe { x: 0, y: [] } (uniqueShares !! 0)
        expectedLen = length firstShare.y
      in
        if expectedLen == 0 then
          Left "Share value is empty"
        else
          let
            allSameLen = foldl (\acc s -> acc && length s.y == expectedLen) true uniqueShares
          in
            if not allSameLen then
              Left "Shares have inconsistent lengths"
            else
              let
                xs = uniqueShares <#> (\s -> fromInt s.x)
                lagrangeCoeffs = mapWithIndex (\j _ -> lagrangeBasisGF xs j) xs

                recoveredBytes = (0 .. (expectedLen - 1)) <#> \byteIdx ->
                  let
                    sumElem = foldl (\acc (shareIdx :: Int) ->
                      let
                        s = fromMaybe { x: 0, y: [] } (uniqueShares !! shareIdx)
                        yVal = fromMaybe 0 (s.y !! byteIdx)
                        yElem = fromInt yVal
                        lj = fromMaybe (fromInt 0) (lagrangeCoeffs !! shareIdx)
                        term = mulGF yElem lj
                      in
                        addGF acc term
                    ) (fromInt 0) (0 .. (numShares - 1))
                  in
                    toInt sumElem
              in
                Right recoveredBytes

-- | Serializes a Share to a hex string format: "XX:YYYYYY..."
shareToHex :: Share -> String
shareToHex s =
  let
    xHex = toHexByte s.x
    yHex = foldl (\acc b -> acc <> toHexByte b) "" s.y
  in
    xHex <> ":" <> yHex
  where
  toHexByte b =
    let
      h = case radix 16 of
        Just r -> toStringAs r (b .&. 0xff)
        Nothing -> "00"
    in
      if length (toCharArray h) == 1 then "0" <> h else h

-- | Parses a Share from a hex string format: "XX:YYYYYY..."
shareFromHex :: String -> Maybe Share
shareFromHex str =
  let
    chars = toCharArray str
    parts = splitOnColon [] chars
  in
    case parts of
      Just { xChars, yChars } ->
        case radix 16 of
          Just r -> do
            xVal <- fromStringAs r (fromCharArray xChars)
            let yVals = parseHexBytes r yChars
            if length yVals > 0 then
              Just { x: xVal, y: yVals }
            else
              Nothing
          Nothing -> Nothing
      Nothing -> Nothing
  where
  splitOnColon acc cs =
    case uncons cs of
      Just { head, tail } ->
        if head == ':' then
          Just { xChars: acc, yChars: tail }
        else
          splitOnColon (acc <> [ head ]) tail
      Nothing -> Nothing

  parseHexBytes r cs =
    let n = length cs
    in if n `mod` 2 /= 0 then []
       else
         let numBytes = n / 2
         in (0 .. (numBytes - 1)) <#> \i ->
           let
             c1 = fromMaybe '0' (cs !! (i * 2))
             c2 = fromMaybe '0' (cs !! (i * 2 + 1))
             pair = fromCharArray [ c1, c2 ]
           in
             fromMaybe 0 (fromStringAs r pair)
