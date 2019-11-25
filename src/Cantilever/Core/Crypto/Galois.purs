module Cantilever.Core.Crypto.Galois
  ( GFElement
  , addGF
  , subGF
  , mulGF
  , divGF
  , invGF
  , powGF
  , polyEvalGF
  , lagrangeBasisGF
  , toInt
  , fromInt
  ) where

import Prelude

import Data.Array ((..), (!!), foldl, length, reverse)
import Data.Int.Bits ((.^.), (.&.), shl, zshr)
import Data.Maybe (fromMaybe)

-- | An element of Galois Field GF(2^8) modulo irreducible polynomial 0x11B.
newtype GFElement = GFElement Int

derive instance eqGFElement :: Eq GFElement
derive instance ordGFElement :: Ord GFElement

instance showGFElement :: Show GFElement where
  show (GFElement x) = "GF(" <> show x <> ")"

toInt :: GFElement -> Int
toInt (GFElement x) = x .&. 0xff

fromInt :: Int -> GFElement
fromInt x = GFElement (x .&. 0xff)

-- | Addition in GF(2^8) is bitwise XOR.
addGF :: GFElement -> GFElement -> GFElement
addGF (GFElement a) (GFElement b) = GFElement (a .^. b)

-- | Subtraction in GF(2^8) is identical to addition (characteristic 2).
subGF :: GFElement -> GFElement -> GFElement
subGF = addGF

-- | Multiplication in GF(2^8) using Russian Peasant multiplication modulo 0x11B.
mulGF :: GFElement -> GFElement -> GFElement
mulGF (GFElement a0) (GFElement b0) = GFElement (go 0 (a0 .&. 0xff) (b0 .&. 0xff) 8)
  where
  go acc _ _ 0 = acc .&. 0xff
  go acc a b steps =
    let
      newAcc = if (b .&. 1) /= 0 then acc .^. a else acc
      hiBit = (a .&. 0x80) /= 0
      shiftedA = (shl a 1) .&. 0xff
      reducedA = if hiBit then shiftedA .^. 0x1b else shiftedA
      shiftedB = zshr b 1
    in
      go newAcc reducedA shiftedB (steps - 1)

-- | Multiplicative inverse in GF(2^8) via exponentiation (Fermat's Little Theorem: a^254 == a^-1).
invGF :: GFElement -> GFElement
invGF a@(GFElement x) =
  if x == 0 then
    GFElement 0
  else
    powGF a 254

-- | Division in GF(2^8).
divGF :: GFElement -> GFElement -> GFElement
divGF a b = mulGF a (invGF b)

-- | Exponentiation by squaring in GF(2^8).
powGF :: GFElement -> Int -> GFElement
powGF _ 0 = GFElement 1
powGF a exp = go (GFElement 1) a exp
  where
  go acc _ 0 = acc
  go acc base e =
    let
      newAcc = if (e .&. 1) /= 0 then mulGF acc base else acc
      newBase = mulGF base base
    in
      go newAcc newBase (zshr e 1)

-- | Evaluates a polynomial with GF(2^8) coefficients at point x.
-- | Coefficients are ordered [c0, c1, c2, ...] representing c0 + c1*x + c2*x^2 + ...
polyEvalGF :: Array GFElement -> GFElement -> GFElement
polyEvalGF coeffs x =
  foldl (\acc c -> addGF c (mulGF acc x)) (GFElement 0) (reverse coeffs)

-- | Computes the Lagrange basis polynomial coefficient L_j(0) = product_{m /= j} (x_m / (x_m - x_j)).
lagrangeBasisGF :: Array GFElement -> Int -> GFElement
lagrangeBasisGF xs j =
  let
    xj = fromMaybe (GFElement 1) (xs !! j)
    n = length xs
  in
    foldl (\acc m ->
      if m == j then
        acc
      else
        let xm = fromMaybe (GFElement 0) (xs !! m)
            num = xm
            denom = subGF xm xj
        in mulGF acc (divGF num denom)
    ) (GFElement 1) (0 .. (n - 1))
