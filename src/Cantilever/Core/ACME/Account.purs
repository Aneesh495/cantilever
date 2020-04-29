-- | Module: Cantilever.Core.ACME.Account
-- | Description: RFC 8555 ACME Account repository, lifecycle transitions, and key rollover.
-- |
-- | Manages account creation, contact updates, deactivation, and RFC 7.5 key change rollover,
-- | indexing accounts by KID (Key Identifier) and by public key thumbprint.

module Cantilever.Core.ACME.Account
  ( AccountStore
  , emptyAccountStore
  , registerAccount
  , lookupAccountById
  , lookupAccountByKey
  , updateAccountContact
  , deactivateAccount
  , keyRollover
  ) where

import Prelude

import Cantilever.Core.ACME.JWS (base64urlEncodeBytes)
import Cantilever.Core.ACME.Types
  ( Account
  , AccountStatus(..)
  , ProblemDocument
  , ProblemType(..)
  )
import Cantilever.Core.Crypto.Key (PublicKey, jwkThumbprintSha256)
import Data.Either (Either(..))
import Data.Map (Map)
import Data.Map as Map
import Data.Maybe (Maybe(..), fromMaybe)

-- | In-memory repository of ACME accounts.
type AccountStore =
  { accountsById  :: Map String Account
  , accountsByKey :: Map String String  -- Thumbprint -> Account ID
  , nextAccountId :: Int
  }

-- | Constructs an empty account store.
emptyAccountStore :: AccountStore
emptyAccountStore =
  { accountsById: Map.empty
  , accountsByKey: Map.empty
  , nextAccountId: 1000
  }

-- | Computes base64url thumbprint string from a public key.
keyThumbprint :: PublicKey -> String
keyThumbprint pubKey =
  base64urlEncodeBytes (fromMaybe [] (jwkThumbprintSha256 pubKey))

-- | Registers a new ACME account. If an account with the same public key already exists,
-- | returns the existing account without duplication (RFC 8555 Section 7.3.1).
registerAccount
  :: AccountStore
  -> Array String
  -> Boolean
  -> PublicKey
  -> Int
  -> { store :: AccountStore, account :: Account, alreadyExisted :: Boolean }
registerAccount store contact agreed pubKey nowEpoch =
  let tp = keyThumbprint pubKey
  in
    case Map.lookup tp store.accountsByKey of
      Just existingId ->
        case Map.lookup existingId store.accountsById of
          Just existingAcct ->
            { store, account: existingAcct, alreadyExisted: true }
          Nothing ->
            createNewAccount store tp contact agreed pubKey nowEpoch
      Nothing ->
        createNewAccount store tp contact agreed pubKey nowEpoch
  where
  createNewAccount s tp cnt ag pk now =
    let
      aid = "acct-" <> show s.nextAccountId
      ordersUrl = "/acme/acct/" <> aid <> "/orders"
      newAcct =
        { id: aid
        , status: AccountValid
        , contact: cnt
        , termsOfServiceAgreed: ag
        , ordersUrl
        , publicKey: pk
        , createdAt: now
        }
      newById = Map.insert aid newAcct s.accountsById
      newByKey = Map.insert tp aid s.accountsByKey
    in
      { store:
          { accountsById: newById
          , accountsByKey: newByKey
          , nextAccountId: s.nextAccountId + 1
          }
      , account: newAcct
      , alreadyExisted: false
      }

-- | Looks up an account by its unique Account ID (KID URL).
lookupAccountById :: AccountStore -> String -> Maybe Account
lookupAccountById store aid =
  Map.lookup aid store.accountsById

-- | Looks up an account by its public key thumbprint.
lookupAccountByKey :: AccountStore -> PublicKey -> Maybe Account
lookupAccountByKey store pubKey = do
  let tp = keyThumbprint pubKey
  aid <- Map.lookup tp store.accountsByKey
  Map.lookup aid store.accountsById

-- | Updates the contact email addresses for an existing active account.
updateAccountContact
  :: AccountStore
  -> String
  -> Array String
  -> Either ProblemDocument AccountStore
updateAccountContact store aid newContact =
  case Map.lookup aid store.accountsById of
    Nothing ->
      Left
        { problemType: AccountDoesNotExist
        , title: "Account Not Found"
        , status: 404
        , detail: "No account exists with ID " <> aid
        , instanceUrl: Nothing
        }
    Just acct ->
      if acct.status /= AccountValid then
        Left
          { problemType: Unauthorized
          , title: "Account Inactive"
          , status: 400
          , detail: "Cannot update contact of an inactive or deactivated account"
          , instanceUrl: Nothing
          }
      else
        let updated = acct { contact = newContact }
            newById = Map.insert aid updated store.accountsById
        in Right (store { accountsById = newById })

-- | Deactivates an account according to RFC 8555 Section 7.3.6.
deactivateAccount
  :: AccountStore
  -> String
  -> Either ProblemDocument AccountStore
deactivateAccount store aid =
  case Map.lookup aid store.accountsById of
    Nothing ->
      Left
        { problemType: AccountDoesNotExist
        , title: "Account Not Found"
        , status: 404
        , detail: "No account exists with ID " <> aid
        , instanceUrl: Nothing
        }
    Just acct ->
      let updated = acct { status = AccountDeactivated }
          newById = Map.insert aid updated store.accountsById
      in Right (store { accountsById = newById })

-- | Performs account key rollover according to RFC 8555 Section 7.5.
keyRollover
  :: AccountStore
  -> String
  -> PublicKey
  -> Either ProblemDocument AccountStore
keyRollover store aid newKey =
  case Map.lookup aid store.accountsById of
    Nothing ->
      Left
        { problemType: AccountDoesNotExist
        , title: "Account Not Found"
        , status: 404
        , detail: "No account exists with ID " <> aid
        , instanceUrl: Nothing
        }
    Just acct ->
      let
        oldTp = keyThumbprint acct.publicKey
        newTp = keyThumbprint newKey
        updatedAcct = acct { publicKey = newKey }
        cleanedByKey = Map.delete oldTp store.accountsByKey
        newByKey = Map.insert newTp aid cleanedByKey
        newById = Map.insert aid updatedAcct store.accountsById
      in
        Right
          { accountsById: newById
          , accountsByKey: newByKey
          , nextAccountId: store.nextAccountId
          }
