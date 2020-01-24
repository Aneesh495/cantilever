module Cantilever.Core.X509.Validity
  ( Validity
  , TimeValue
  , makeValidity
  , validityFromSeconds
  , nowEpochSeconds
  , parseTimeString
  , formatTimeValue
  , encodeValidityAst
  , decodeValidityAst
  , isValidAt
  , isValidWithSkew
  , isExpiredAt
  , isNotYetValidAt
  , validityDurationSeconds
  ) where

import Prelude

import Cantilever.Core.ASN1.Types (ASN1(..), ASN1Value(..), TagForm(..), makeUniversalTag)
import Data.Maybe (Maybe(..))
import Effect (Effect)

-- | Represents an ASN.1 Time string with metadata indicating whether it is UTCTime or GeneralizedTime.
type TimeValue =
  { epochSeconds :: Int
  , timeString :: String
  , isUtcTime :: Boolean
  }

-- | Certificate Validity period per RFC 5280 Section 4.1.2.5.
type Validity =
  { notBefore :: TimeValue
  , notAfter :: TimeValue
  }

foreign import nowEpochSecondsImpl :: Effect Int
foreign import parseTimeStringToEpochSecondsImpl :: (forall a. a -> Maybe a) -> (forall a. Maybe a) -> String -> Maybe Int
foreign import formatEpochSecondsToAsn1TimeImpl :: Int -> { isUtcTime :: Boolean, timeString :: String }

-- | Retrieves current system clock in seconds since Unix epoch.
nowEpochSeconds :: Effect Int
nowEpochSeconds = nowEpochSecondsImpl

-- | Parses an ASN.1 UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ) string.
parseTimeString :: String -> Maybe TimeValue
parseTimeString str =
  case parseTimeStringToEpochSecondsImpl Just Nothing str of
    Just sec ->
      let res = formatEpochSecondsToAsn1TimeImpl sec
      in Just { epochSeconds: sec, timeString: str, isUtcTime: res.isUtcTime }
    Nothing -> Nothing

-- | Formats epoch seconds into a TimeValue with appropriate UTCTime or GeneralizedTime string.
formatTimeValue :: Int -> TimeValue
formatTimeValue sec =
  let res = formatEpochSecondsToAsn1TimeImpl sec
  in { epochSeconds: sec, timeString: res.timeString, isUtcTime: res.isUtcTime }

-- | Creates a Validity window from notBefore and notAfter epoch seconds.
validityFromSeconds :: Int -> Int -> Validity
validityFromSeconds startSec endSec =
  { notBefore: formatTimeValue startSec
  , notAfter: formatTimeValue endSec
  }

-- | Creates a Validity window with default duration in days starting from now.
makeValidity :: Int -> Int -> Validity
makeValidity startOffsetSec durationDays =
  let
    start = startOffsetSec
    end = start + durationDays * 86400
  in
    validityFromSeconds start end

-- | Checks whether targetTime falls strictly within [notBefore, notAfter].
isValidAt :: Int -> Validity -> Boolean
isValidAt targetTime val =
  targetTime >= val.notBefore.epochSeconds && targetTime <= val.notAfter.epochSeconds

-- | Checks whether targetTime falls within [notBefore - skew, notAfter + skew].
isValidWithSkew :: Int -> Int -> Validity -> Boolean
isValidWithSkew skewSeconds targetTime val =
  targetTime >= (val.notBefore.epochSeconds - skewSeconds) &&
  targetTime <= (val.notAfter.epochSeconds + skewSeconds)

-- | Checks whether certificate is expired at targetTime.
isExpiredAt :: Int -> Validity -> Boolean
isExpiredAt targetTime val = targetTime > val.notAfter.epochSeconds

-- | Checks whether certificate is not yet valid at targetTime.
isNotYetValidAt :: Int -> Validity -> Boolean
isNotYetValidAt targetTime val = targetTime < val.notBefore.epochSeconds

-- | Computes total validity period in seconds.
validityDurationSeconds :: Validity -> Int
validityDurationSeconds val = val.notAfter.epochSeconds - val.notBefore.epochSeconds

-- | Encodes Validity into an ASN.1 Sequence [ Time, Time ].
encodeValidityAst :: Validity -> ASN1
encodeValidityAst val =
  let
    nbAst = encodeTimeAst val.notBefore
    naAst = encodeTimeAst val.notAfter
    seqTag = makeUniversalTag 16 Constructed
  in
    ASN1 seqTag (ASN1Sequence [ nbAst, naAst ])
  where
  encodeTimeAst tv =
    if tv.isUtcTime then
      ASN1 (makeUniversalTag 23 Primitive) (ASN1UTCTime tv.timeString)
    else
      ASN1 (makeUniversalTag 24 Primitive) (ASN1GeneralizedTime tv.timeString)

-- | Decodes an ASN.1 Validity Sequence into a Validity record.
decodeValidityAst :: ASN1 -> Maybe Validity
decodeValidityAst (ASN1 _ (ASN1Sequence [ nbAst, naAst ])) = do
  nb <- decodeTimeAst nbAst
  na <- decodeTimeAst naAst
  Just { notBefore: nb, notAfter: na }
  where
  decodeTimeAst (ASN1 _ (ASN1UTCTime s)) = parseTimeString s
  decodeTimeAst (ASN1 _ (ASN1GeneralizedTime s)) = parseTimeString s
  decodeTimeAst _ = Nothing
decodeValidityAst _ = Nothing
