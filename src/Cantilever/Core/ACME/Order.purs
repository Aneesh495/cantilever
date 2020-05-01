-- | Module: Cantilever.Core.ACME.Order
-- | Description: RFC 8555 ACME Order and Authorization state machine engine.
-- |
-- | Manages order creation, challenge assignment, authorization status tracking,
-- | state transitions (pending -> ready -> processing -> valid), and CSR finalization.

module Cantilever.Core.ACME.Order
  ( OrderStore
  , emptyOrderStore
  , createOrder
  , lookupOrder
  , lookupAuthz
  , updateAuthzStatus
  , updateChallengeStatus
  , checkOrderReadiness
  , finalizeOrder
  ) where

import Prelude

import Cantilever.Core.ACME.Types
  ( Authorization
  , AuthorizationStatus(..)
  , Challenge
  , ChallengeStatus(..)
  , ChallengeType(..)
  , Identifier(..)
  , Order
  , OrderStatus(..)
  , ProblemDocument
  , ProblemType(..)
  )
import Cantilever.Core.X509.CSR (CertificationRequest, verifyCSRSignature)
import Data.Array (all, foldl, last, uncons)
import Data.Either (Either(..))
import Data.Map (Map)
import Data.Map as Map
import Data.Maybe (Maybe(..))
import Data.String.Common (split)
import Data.String.Pattern (Pattern(..))

-- | In-memory store for orders and authorizations.
type OrderStore =
  { orders       :: Map String Order
  , authzs       :: Map String Authorization
  , nextOrderId  :: Int
  , nextAuthzId  :: Int
  }

-- | Constructs an empty order store.
emptyOrderStore :: OrderStore
emptyOrderStore =
  { orders: Map.empty
  , authzs: Map.empty
  , nextOrderId: 2000
  , nextAuthzId: 5000
  }

-- | Creates a new order for an account with authorizations and challenges.
createOrder
  :: OrderStore
  -> String
  -> Array Identifier
  -> Maybe Int
  -> Maybe Int
  -> Int
  -> { store :: OrderStore, order :: Order, authzs :: Array Authorization }
createOrder store acctId idents notBef notAft nowEpoch =
  let
    oid = "order-" <> show store.nextOrderId
    finalizeUrl = "/acme/order/" <> oid <> "/finalize"
    expires = Just (nowEpoch + 86400 * 7) -- 7 days

    -- Create authorization objects for each identifier
    authzResults = foldl (\acc ident ->
      let aid = "authz-" <> show acc.nextId
          httpTok = "tok-http-" <> show acc.nextId <> "-" <> show nowEpoch
          dnsTok = "tok-dns-" <> show acc.nextId <> "-" <> show nowEpoch

          httpChal :: Challenge
          httpChal =
            { challengeType: Http01
            , url: "/acme/chal/" <> aid <> "/http-01"
            , status: ChallengePending
            , token: httpTok
            , validatedAt: Nothing
            , error: Nothing
            }

          dnsChal :: Challenge
          dnsChal =
            { challengeType: Dns01
            , url: "/acme/chal/" <> aid <> "/dns-01"
            , status: ChallengePending
            , token: dnsTok
            , validatedAt: Nothing
            , error: Nothing
            }

          authz :: Authorization
          authz =
            { id: aid
            , identifier: ident
            , status: AuthzPending
            , expires
            , challenges: [httpChal, dnsChal]
            , wildcard: isWildcard ident
            }
      in
        { nextId: acc.nextId + 1
        , authzList: acc.authzList <> [authz]
        }
    ) { nextId: store.nextAuthzId, authzList: [] } idents

    newAuthzs = authzResults.authzList
    authzUrls = map (\a -> "/acme/authz/" <> a.id) newAuthzs

    order :: Order
    order =
      { id: oid
      , accountId: acctId
      , status: OrderPending
      , expires
      , identifiers: idents
      , notBefore: notBef
      , notAfter: notAft
      , error: Nothing
      , authorizationUrls: authzUrls
      , finalizeUrl
      , certificateUrl: Nothing
      }

    updatedOrders = Map.insert oid order store.orders
    updatedAuthzs = foldl (\m a -> Map.insert a.id a m) store.authzs newAuthzs
  in
    { store:
        { orders: updatedOrders
        , authzs: updatedAuthzs
        , nextOrderId: store.nextOrderId + 1
        , nextAuthzId: authzResults.nextId
        }
    , order
    , authzs: newAuthzs
    }
  where
  isWildcard (DnsIdentifier name) =
    case uncons (split (Pattern "*.") name) of
      Just { head: "" } -> true
      _ -> false
  isWildcard _ = false

-- | Looks up an order by its ID.
lookupOrder :: OrderStore -> String -> Maybe Order
lookupOrder store oid = Map.lookup oid store.orders

-- | Looks up an authorization by its ID.
lookupAuthz :: OrderStore -> String -> Maybe Authorization
lookupAuthz store aid = Map.lookup aid store.authzs

-- | Updates the status of an authorization.
updateAuthzStatus
  :: OrderStore
  -> String
  -> AuthorizationStatus
  -> OrderStore
updateAuthzStatus store aid newStatus =
  case Map.lookup aid store.authzs of
    Nothing -> store
    Just authz ->
      let updated = authz { status = newStatus }
      in store { authzs = Map.insert aid updated store.authzs }

-- | Updates the status of an individual challenge within an authorization.
updateChallengeStatus
  :: OrderStore
  -> String
  -> ChallengeType
  -> ChallengeStatus
  -> Maybe ProblemDocument
  -> OrderStore
updateChallengeStatus store aid cType newStatus maybeErr =
  case Map.lookup aid store.authzs of
    Nothing -> store
    Just authz ->
      let
        updatedChals = map (\c ->
          if c.challengeType == cType then
            c { status = newStatus, error = maybeErr }
          else c
        ) authz.challenges

        -- If challenge became valid, authorization becomes valid
        newAuthzStatus =
          if newStatus == ChallengeValid then AuthzValid
          else if newStatus == ChallengeInvalid then AuthzInvalid
          else authz.status

        updatedAuthz = authz { challenges = updatedChals, status = newAuthzStatus }
      in
        store { authzs = Map.insert aid updatedAuthz store.authzs }

-- | Evaluates whether all authorizations for an order are valid, transitioning it to ready.
checkOrderReadiness :: OrderStore -> String -> OrderStore
checkOrderReadiness store oid =
  case Map.lookup oid store.orders of
    Nothing -> store
    Just order ->
      if order.status /= OrderPending then store
      else
        let
          isAuthzValid url =
            let aid = extractIdFromUrl url
            in case Map.lookup aid store.authzs of
              Just a -> a.status == AuthzValid
              Nothing -> false

          allValid = all isAuthzValid order.authorizationUrls
          newStatus = if allValid then OrderReady else OrderPending
        in
          store { orders = Map.insert oid (order { status = newStatus }) store.orders }
  where
  extractIdFromUrl u =
    let parts = split (Pattern "/") u
    in case last parts of
      Just lastPart -> lastPart
      Nothing -> u

-- | Finalizes an order upon receiving a valid PKCS#10 CSR.
-- | Verifies proof of possession and advances state to processing / valid.
finalizeOrder
  :: OrderStore
  -> String
  -> CertificationRequest
  -> String
  -> Either ProblemDocument { store :: OrderStore, order :: Order }
finalizeOrder store oid csr certUrl =
  case Map.lookup oid store.orders of
    Nothing ->
      Left
        { problemType: Malformed
        , title: "Order Not Found"
        , status: 404
        , detail: "No order exists with ID " <> oid
        , instanceUrl: Nothing
        }
    Just order ->
      if order.status /= OrderReady && order.status /= OrderProcessing then
        Left
          { problemType: OrderNotReady
          , title: "Order Not Ready"
          , status: 403
          , detail: "Order status is " <> show order.status <> ", but must be ready to finalize"
          , instanceUrl: Nothing
          }
      else
        -- Verify CSR signature proof of possession
        if not (verifyCSRSignature csr) then
          Left
            { problemType: BadCSR
            , title: "Invalid CSR Signature"
            , status: 400
            , detail: "The CSR signature could not be verified with the subject public key"
            , instanceUrl: Nothing
            }
        else
          let updatedOrder = order
                { status = OrderValid
                , certificateUrl = Just certUrl
                }
              newOrders = Map.insert oid updatedOrder store.orders
          in
            Right
              { store: store { orders = newOrders }
              , order: updatedOrder
              }
