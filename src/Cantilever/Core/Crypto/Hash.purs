module Cantilever.Core.Crypto.Hash
  ( DigestAlgorithm(..)
  , digest
  , sha1
  , sha256
  , sha384
  , sha512
  , md5
  , hmacSha256
  , toHex
  , fromHex
  ) where

import Prelude

import Data.Maybe (Maybe(..))

-- | Supported cryptographic digest algorithms.
data DigestAlgorithm
  = SHA1
  | SHA256
  | SHA384
  | SHA512
  | MD5

derive instance eqDigestAlgorithm :: Eq DigestAlgorithm
derive instance ordDigestAlgorithm :: Ord DigestAlgorithm

instance showDigestAlgorithm :: Show DigestAlgorithm where
  show = case _ of
    SHA1 -> "SHA-1"
    SHA256 -> "SHA-256"
    SHA384 -> "SHA-384"
    SHA512 -> "SHA-512"
    MD5 -> "MD5"

foreign import sha1Impl :: Array Int -> Array Int
foreign import sha256Impl :: Array Int -> Array Int
foreign import sha384Impl :: Array Int -> Array Int
foreign import sha512Impl :: Array Int -> Array Int
foreign import md5Impl :: Array Int -> Array Int
foreign import hmacSha256Impl :: Array Int -> Array Int -> Array Int
foreign import toHexImpl :: Array Int -> String
foreign import fromHexImpl :: (forall a. a -> Maybe a) -> (forall a. Maybe a) -> String -> Maybe (Array Int)

-- | Computes message digest according to the specified algorithm.
digest :: DigestAlgorithm -> Array Int -> Array Int
digest = case _ of
  SHA1 -> sha1Impl
  SHA256 -> sha256Impl
  SHA384 -> sha384Impl
  SHA512 -> sha512Impl
  MD5 -> md5Impl

sha1 :: Array Int -> Array Int
sha1 = sha1Impl

sha256 :: Array Int -> Array Int
sha256 = sha256Impl

sha384 :: Array Int -> Array Int
sha384 = sha384Impl

sha512 :: Array Int -> Array Int
sha512 = sha512Impl

md5 :: Array Int -> Array Int
md5 = md5Impl

hmacSha256 :: Array Int -> Array Int -> Array Int
hmacSha256 = hmacSha256Impl

toHex :: Array Int -> String
toHex = toHexImpl

fromHex :: String -> Maybe (Array Int)
fromHex = fromHexImpl Just Nothing
