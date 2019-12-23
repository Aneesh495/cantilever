module Cantilever.Core.ASN1.Types
  ( TagClass(..)
  , TagForm(..)
  , ASN1Tag(..)
  , ASN1Value(..)
  , ASN1(..)
  , tagNumber
  , isConstructed
  , makeUniversalTag
  , makeContextTag
  ) where

import Prelude

import Cantilever.Core.Crypto.BigInt (BigInt)
import Data.Array (length)

-- | ASN.1 Tag Class according to ITU-T X.690 / ISO/IEC 8825-1.
data TagClass
  = Universal
  | Application
  | ContextSpecific
  | Private

derive instance eqTagClass :: Eq TagClass
derive instance ordTagClass :: Ord TagClass

instance showTagClass :: Show TagClass where
  show = case _ of
    Universal -> "Universal"
    Application -> "Application"
    ContextSpecific -> "ContextSpecific"
    Private -> "Private"

-- | ASN.1 Primitive vs Constructed encoding form.
data TagForm
  = Primitive
  | Constructed

derive instance eqTagForm :: Eq TagForm
derive instance ordTagForm :: Ord TagForm

instance showTagForm :: Show TagForm where
  show = case _ of
    Primitive -> "Primitive"
    Constructed -> "Constructed"

-- | Complete ASN.1 Tag metadata.
data ASN1Tag = ASN1Tag
  { tagClass :: TagClass
  , tagForm :: TagForm
  , tagNumber :: Int
  }

derive instance eqASN1Tag :: Eq ASN1Tag
derive instance ordASN1Tag :: Ord ASN1Tag

instance showASN1Tag :: Show ASN1Tag where
  show (ASN1Tag t) =
    "Tag(" <> show t.tagClass <> ", " <> show t.tagForm <> ", " <> show t.tagNumber <> ")"

tagNumber :: ASN1Tag -> Int
tagNumber (ASN1Tag t) = t.tagNumber

isConstructed :: ASN1Tag -> Boolean
isConstructed (ASN1Tag t) = t.tagForm == Constructed

-- | Creates a Universal tag with specified number and form.
makeUniversalTag :: Int -> TagForm -> ASN1Tag
makeUniversalTag num form = ASN1Tag
  { tagClass: Universal
  , tagForm: form
  , tagNumber: num
  }

-- | Creates a Context-Specific tag [n].
makeContextTag :: Int -> TagForm -> ASN1Tag
makeContextTag num form = ASN1Tag
  { tagClass: ContextSpecific
  , tagForm: form
  , tagNumber: num
  }

-- | Typed ASN.1 semantic value representation.
data ASN1Value
  = ASN1Boolean Boolean
  | ASN1Integer BigInt
  | ASN1BitString Int (Array Int) -- unused bit count (0..7) and octets
  | ASN1OctetString (Array Int)
  | ASN1Null
  | ASN1OID (Array Int)
  | ASN1UTF8String String
  | ASN1PrintableString String
  | ASN1IA5String String
  | ASN1UTCTime String
  | ASN1GeneralizedTime String
  | ASN1Sequence (Array ASN1)
  | ASN1Set (Array ASN1)
  | ASN1ContextExplicit Int ASN1
  | ASN1ContextImplicit Int (Array Int)
  | ASN1Raw (Array Int)

derive instance eqASN1Value :: Eq ASN1Value

-- | Complete ASN.1 element comprising tag and value.
data ASN1 = ASN1 ASN1Tag ASN1Value

derive instance eqASN1 :: Eq ASN1

instance showASN1 :: Show ASN1 where
  show (ASN1 tag val) =
    "ASN1(" <> show tag <> ", " <> showValue val <> ")"
    where
    showValue = case _ of
      ASN1Boolean b -> "Boolean(" <> show b <> ")"
      ASN1Integer i -> "Integer(" <> show i <> ")"
      ASN1BitString unused bytes -> "BitString(unused=" <> show unused <> ", len=" <> show (length bytes) <> ")"
      ASN1OctetString bytes -> "OctetString(len=" <> show (length bytes) <> ")"
      ASN1Null -> "Null"
      ASN1OID components -> "OID(" <> show components <> ")"
      ASN1UTF8String s -> "UTF8String(" <> show s <> ")"
      ASN1PrintableString s -> "PrintableString(" <> show s <> ")"
      ASN1IA5String s -> "IA5String(" <> show s <> ")"
      ASN1UTCTime s -> "UTCTime(" <> s <> ")"
      ASN1GeneralizedTime s -> "GeneralizedTime(" <> s <> ")"
      ASN1Sequence elems -> "Sequence(count=" <> show (length elems) <> ")"
      ASN1Set elems -> "Set(count=" <> show (length elems) <> ")"
      ASN1ContextExplicit n inner -> "ContextExplicit[" <> show n <> "](" <> show inner <> ")"
      ASN1ContextImplicit n bytes -> "ContextImplicit[" <> show n <> "](len=" <> show (length bytes) <> ")"
      ASN1Raw bytes -> "Raw(len=" <> show (length bytes) <> ")"
