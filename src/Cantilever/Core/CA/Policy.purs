-- | Module: Cantilever.Core.CA.Policy
-- | Description: CA/Browser Forum (CABF) Baseline Requirements policy linter.
-- |
-- | Enforces strict validation on maximum certificate lifetime (398 days),
-- | RSA modulus bit length (minimum 2048-bit), prohibited internal TLDs (.local, .internal),
-- | invalid wildcard positions (*.com, *.*.domain), and public key algorithm constraints.

module Cantilever.Core.CA.Policy
  ( PolicyViolation
  , PolicyResult(..)
  , lintCertificateRequest
  , isInternalDomain
  , isDisallowedWildcard
  ) where

import Prelude

import Cantilever.Core.Crypto.Key (KeyAlgorithm(..), PublicKey)
import Data.Array (filter, length, reverse, uncons)
import Data.Maybe (Maybe(..))
import Data.String.Common (split, toLower)
import Data.String.Pattern (Pattern(..))

-- | A specific policy rule violation.
type PolicyViolation =
  { code    :: String
  , message :: String
  }

-- | Outcome of policy linting.
data PolicyResult
  = PolicyPass
  | PolicyFail (Array PolicyViolation)

derive instance eqPolicyResult :: Eq PolicyResult

instance showPolicyResult :: Show PolicyResult where
  show PolicyPass = "PolicyPass"
  show (PolicyFail errs) = "PolicyFail(" <> show (length errs) <> " violations)"

-- | Disallowed non-public top-level domains according to CABF guidelines.
internalTlds :: Array String
internalTlds =
  [ "local"
  , "internal"
  , "lan"
  , "home"
  , "corp"
  , "test"
  , "example"
  , "invalid"
  , "localhost"
  ]

-- | Checks if a hostname uses an unresolvable or internal TLD.
isInternalDomain :: String -> Boolean
isInternalDomain domain =
  let parts = split (Pattern ".") (toLower domain)
  in case uncons parts of
    Nothing -> true
    Just _ ->
      let rev = split (Pattern ".") (toLower domain)
      in case uncons (reverse rev) of
        Just { head: tld } ->
          case filter (\t -> t == tld) internalTlds of
            [] -> false
            _ -> true
        Nothing -> true

-- | Disallowed top-level wildcard suffixes.
publicSuffixes :: Array String
publicSuffixes = ["com", "org", "net", "edu", "gov", "mil", "io", "co", "dev", "app"]

-- | Checks whether a wildcard pattern is improperly placed or targets a public suffix.
-- | Examples of invalid: "*.com", "*.*.example.com", "foo.*.com"
isDisallowedWildcard :: String -> Boolean
isDisallowedWildcard domain =
  let lower = toLower domain
      parts = split (Pattern ".") lower
  in
    case uncons parts of
      Just { head: "*", tail: rest } ->
        case rest of
          [singleTld] ->
            -- Disallows *.com, *.org, etc.
            case filter (\s -> s == singleTld) publicSuffixes of
              [] -> false
              _ -> true
          _ ->
            -- Check for multiple wildcards in domain
            let asteriskCount = length (filter (\p -> p == "*") parts)
            in asteriskCount > 1
      _ ->
        -- Contains wildcard not at start
        let asteriskCount = length (filter (\p -> p == "*") parts)
        in asteriskCount > 0

-- | Lints an end-entity certificate request against CABF Baseline Requirements.
lintCertificateRequest
  :: Array String
  -> PublicKey
  -> Int
  -> PolicyResult
lintCertificateRequest sans pubKey durationDays =
  let
    v1 = checkLifetime durationDays
    v2 = checkKeyLength pubKey
    v3 = checkDomainNames sans
    allViolations = v1 <> v2 <> v3
  in
    case allViolations of
      [] -> PolicyPass
      errs -> PolicyFail errs
  where
  -- Rule 1: Max validity 398 days (Apple / Google / Mozilla root program requirement)
  checkLifetime days =
    if days > 398 then
      [ { code: "CABF_MAX_VALIDITY_EXCEEDED"
        , message: "Certificate validity period of " <> show days <> " days exceeds maximum allowed 398 days"
        }
      ]
    else if days <= 0 then
      [ { code: "CABF_INVALID_VALIDITY"
        , message: "Certificate validity period must be positive"
        }
      ]
    else []

  -- Rule 2: Minimum RSA key size 2048 bits
  checkKeyLength pk =
    case pk.algorithm of
      RSA2048 -> []
      RSA4096 -> []
      ECDSA_P256 -> []
      ECDSA_P384 -> []
      Ed25519 -> []

  -- Rule 3: Validate each SAN domain name
  checkDomainNames names =
    names >>= lintSingleDomain

  lintSingleDomain name =
    let
      vInternal =
        if isInternalDomain name then
          [ { code: "CABF_INTERNAL_NAME_PROHIBITED"
            , message: "Domain " <> name <> " uses a prohibited internal TLD"
            }
          ]
        else []
      vWildcard =
        if isDisallowedWildcard name then
          [ { code: "CABF_INVALID_WILDCARD_SYNTAX"
            , message: "Domain " <> name <> " specifies an invalid or overly broad wildcard pattern"
            }
          ]
        else []
    in
      vInternal <> vWildcard
