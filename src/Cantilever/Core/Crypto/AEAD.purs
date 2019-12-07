module Cantilever.Core.Crypto.AEAD
  ( EncryptedPayload
  , encryptAesGcm
  , decryptAesGcm
  , deriveKeyPbkdf2
  ) where

import Data.Maybe (Maybe(..))

-- | Encrypted payload containing ciphertext and 16-byte authentication tag.
type EncryptedPayload =
  { ciphertext :: Array Int
  , tag :: Array Int
  }

foreign import encryptAesGcmImpl :: Array Int -> Array Int -> Array Int -> Array Int -> EncryptedPayload
foreign import decryptAesGcmImpl :: (forall a. a -> Maybe a) -> (forall a. Maybe a) -> Array Int -> Array Int -> Array Int -> Array Int -> Array Int -> Maybe (Array Int)
foreign import pbkdf2Impl :: String -> Array Int -> Int -> Int -> Array Int

-- | Encrypts plaintext using AES-256-GCM with a 32-byte key and 12-byte IV.
encryptAesGcm :: Array Int -> Array Int -> Array Int -> Array Int -> EncryptedPayload
encryptAesGcm key iv plaintext aad =
  encryptAesGcmImpl key iv plaintext aad

-- | Decrypts ciphertext using AES-256-GCM, verifying the 16-byte authentication tag.
decryptAesGcm :: Array Int -> Array Int -> Array Int -> Array Int -> Array Int -> Maybe (Array Int)
decryptAesGcm key iv ciphertext tag aad =
  decryptAesGcmImpl Just Nothing key iv ciphertext tag aad

-- | Derives a cryptographic key using PBKDF2-HMAC-SHA256.
deriveKeyPbkdf2 :: String -> Array Int -> Int -> Int -> Array Int
deriveKeyPbkdf2 passphrase salt iterations keyLen =
  pbkdf2Impl passphrase salt iterations keyLen
