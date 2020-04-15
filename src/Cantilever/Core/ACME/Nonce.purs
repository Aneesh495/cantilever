-- | Module: Cantilever.Core.ACME.Nonce
-- | Description: Anti-replay Nonce generator and validator for RFC 8555 Section 6.5.
-- |
-- | Manages cryptographically random base64url replay-nonces with bounded lifetime,
-- | enforcing strict single-use consumption to prevent replay attacks.

module Cantilever.Core.ACME.Nonce
  ( NonceStore
  , NonceEntry
  , emptyNonceStore
  , generateNonce
  , consumeNonce
  , pruneExpiredNonces
  , activeNonceCount
  ) where

import Prelude

import Cantilever.Core.ACME.Types (ProblemDocument, ProblemType(..))
import Data.Either (Either(..))
import Data.Map (Map)
import Data.Map as Map
import Data.Maybe (Maybe(..))
import Effect (Effect)

-- | Foreign JS bindings for cryptographic random generation.
foreign import generateRandomNonceRaw :: Effect String
foreign import getCurrentTimeMillis :: Effect Number

-- | Nonce entry storing creation timestamp in milliseconds.
type NonceEntry =
  { createdAtMs :: Number
  }

-- | In-memory nonce store with configured TTL.
type NonceStore =
  { nonces :: Map String NonceEntry
  , ttlMs  :: Number
  }

-- | Constructs an empty nonce store with default 5-minute TTL (300,000 ms).
emptyNonceStore :: Number -> NonceStore
emptyNonceStore ttl =
  { nonces: Map.empty
  , ttlMs: ttl
  }

-- | Generates a new cryptographically random nonce and inserts it into the store.
generateNonce :: NonceStore -> Effect { store :: NonceStore, nonce :: String }
generateNonce store = do
  nonceStr <- generateRandomNonceRaw
  nowMs <- getCurrentTimeMillis
  let entry = { createdAtMs: nowMs }
      updatedMap = Map.insert nonceStr entry store.nonces
  pure { store: store { nonces = updatedMap }, nonce: nonceStr }

-- | Validates and consumes a single-use nonce.
-- | Fails with RFC 8555 BadNonce error if missing or expired.
consumeNonce
  :: NonceStore
  -> String
  -> Number
  -> Either ProblemDocument NonceStore
consumeNonce store nonceStr nowMs =
  case Map.lookup nonceStr store.nonces of
    Nothing ->
      Left
        { problemType: BadNonce
        , title: "Bad Nonce"
        , status: 400
        , detail: "The request did not specify an existing, valid replay-nonce"
        , instanceUrl: Nothing
        }
    Just entry ->
      let age = nowMs - entry.createdAtMs
      in
        if age > store.ttlMs then
          Left
            { problemType: BadNonce
            , title: "Bad Nonce"
            , status: 400
            , detail: "The specified replay-nonce has expired"
            , instanceUrl: Nothing
            }
        else
          let updatedMap = Map.delete nonceStr store.nonces
          in Right (store { nonces = updatedMap })

-- | Prunes nonces older than TTL.
pruneExpiredNonces :: NonceStore -> Number -> NonceStore
pruneExpiredNonces store nowMs =
  let
    filteredMap = Map.filter (\entry -> (nowMs - entry.createdAtMs) <= store.ttlMs) store.nonces
  in
    store { nonces = filteredMap }

-- | Returns the count of active nonces in the store.
activeNonceCount :: NonceStore -> Int
activeNonceCount store = Map.size store.nonces
