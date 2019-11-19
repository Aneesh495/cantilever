module Cantilever.Core.Crypto.BigInt
  ( BigInt
  , fromInt
  , fromString
  , fromHexString
  , toString
  , toHexString
  , toOctets
  , fromOctets
  , powMod
  , bitLength
  , bigZero
  , bigOne
  , bigGcd
  ) where

import Prelude hiding (gcd, zero, one)
import Prelude as P

import Data.Maybe (Maybe(..))

-- | Arbitrary-precision integer type used throughout certificate serial numbers,
-- | RSA modulus calculations, and ASN.1 integer encoding.
foreign import data BigInt :: Type

foreign import fromIntImpl :: Int -> BigInt
foreign import fromStringImpl :: (forall a. a -> Maybe a) -> (forall a. Maybe a) -> String -> Maybe BigInt
foreign import toStringImpl :: Int -> BigInt -> String
foreign import addImpl :: BigInt -> BigInt -> BigInt
foreign import subImpl :: BigInt -> BigInt -> BigInt
foreign import mulImpl :: BigInt -> BigInt -> BigInt
foreign import divImpl :: BigInt -> BigInt -> BigInt
foreign import modImpl :: BigInt -> BigInt -> BigInt
foreign import eqImpl :: BigInt -> BigInt -> Boolean
foreign import compareImpl :: Ordering -> Ordering -> Ordering -> BigInt -> BigInt -> Ordering
foreign import powModImpl :: BigInt -> BigInt -> BigInt -> BigInt
foreign import toOctetsImpl :: BigInt -> Array Int
foreign import fromOctetsImpl :: Array Int -> BigInt
foreign import bitLengthImpl :: BigInt -> Int

instance eqBigInt :: Eq BigInt where
  eq = eqImpl

instance ordBigInt :: Ord BigInt where
  compare = compareImpl LT EQ GT

instance showBigInt :: Show BigInt where
  show = toStringImpl 10

instance semiringBigInt :: Semiring BigInt where
  add = addImpl
  zero = fromIntImpl 0
  mul = mulImpl
  one = fromIntImpl 1

instance ringBigInt :: Ring BigInt where
  sub = subImpl

instance commutativeRingBigInt :: CommutativeRing BigInt

instance euclideanRingBigInt :: EuclideanRing BigInt where
  degree _ = 1
  div = divImpl
  mod = modImpl

fromInt :: Int -> BigInt
fromInt = fromIntImpl

fromString :: String -> Maybe BigInt
fromString = fromStringImpl Just Nothing

fromHexString :: String -> Maybe BigInt
fromHexString hex = fromString ("0x" <> hex)

toString :: BigInt -> String
toString = toStringImpl 10

toHexString :: BigInt -> String
toHexString = toStringImpl 16

toOctets :: BigInt -> Array Int
toOctets = toOctetsImpl

fromOctets :: Array Int -> BigInt
fromOctets = fromOctetsImpl

powMod :: BigInt -> BigInt -> BigInt -> BigInt
powMod = powModImpl

bitLength :: BigInt -> Int
bitLength = bitLengthImpl

bigZero :: BigInt
bigZero = fromIntImpl 0

bigOne :: BigInt
bigOne = fromIntImpl 1

-- | Euclidean algorithm for greatest common divisor on arbitrary-precision integers.
bigGcd :: BigInt -> BigInt -> BigInt
bigGcd a b =
  if b == bigZero then
    a
  else
    bigGcd b (a `P.mod` b)
