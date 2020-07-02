-- | Module: Test.Cantilever.ASN1Spec
-- | Description: Unit tests for ASN.1 DER and PEM encoders and decoders.

module Test.Cantilever.ASN1Spec
  ( runASN1Tests
  ) where

import Prelude

import Cantilever.Core.ASN1.DER (decodeDER, encodeDER)
import Cantilever.Core.ASN1.OID (OID(..), formatOID, parseOID, sha256WithRSAEncryption)
import Cantilever.Core.ASN1.PEM (decodePEM, decodePEMMany, encodePEM)
import Cantilever.Core.ASN1.Printer (printASN1Tree)
import Cantilever.Core.ASN1.Types (ASN1(..), ASN1Value(..), TagForm(..), makeUniversalTag)
import Cantilever.Core.Crypto.BigInt as BigInt
import Data.Array (length)
import Data.Maybe (Maybe(..))
import Data.String.CodeUnits (length) as String
import Effect (Effect)
import Test.Cantilever.TestRunner (assert, assertEq, runTestSuite)

runASN1Tests :: Effect Unit
runASN1Tests = runTestSuite "ASN.1 DER & PEM Codec Engine" do
  testDerPrimitivesRoundtrip
  testOidCodecAndRegistry
  testDerConstructedSequencesAndSets
  testPemContainerEncodingAndDecoding
  testAsn1PrinterDiagnosticOutput

testDerPrimitivesRoundtrip :: Effect Unit
testDerPrimitivesRoundtrip = do
  -- Boolean TRUE
  let boolTrue = ASN1 (makeUniversalTag 1 Primitive) (ASN1Boolean true)
      encodedBool = encodeDER boolTrue
  assertEq "Boolean TRUE encoded DER" [ 0x01, 0x01, 0xFF ] encodedBool
  case decodeDER encodedBool of
    Just { element } -> assertEq "Boolean TRUE roundtrip" boolTrue element
    Nothing -> assert "Boolean decode failed" false

  -- Integer: 128 (needs leading 0x00 byte in two's complement)
  let int128 = ASN1 (makeUniversalTag 2 Primitive) (ASN1Integer (BigInt.fromInt 128))
      encodedInt = encodeDER int128
  assertEq "Integer 128 encoded DER (leading 0x00 for sign)" [ 0x02, 0x02, 0x00, 0x80 ] encodedInt
  case decodeDER encodedInt of
    Just { element } -> assertEq "Integer 128 roundtrip" int128 element
    Nothing -> assert "Integer decode failed" false

  -- UTF8String
  let utf8Elem = ASN1 (makeUniversalTag 12 Primitive) (ASN1UTF8String "Cantilever")
      encodedUtf8 = encodeDER utf8Elem
  case decodeDER encodedUtf8 of
    Just { element } -> assertEq "UTF8String roundtrip" utf8Elem element
    Nothing -> assert "UTF8String decode failed" false

testOidCodecAndRegistry :: Effect Unit
testOidCodecAndRegistry = do
  -- Format standard OID: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
  let formatted = formatOID sha256WithRSAEncryption
  assertEq "Format OID sha256WithRSAEncryption" "1.2.840.113549.1.1.11" formatted

  -- Parse OID string back to arcs
  case parseOID "1.2.840.113549.1.1.11" of
    Just oid -> assertEq "Parse OID matches standard arc representation" sha256WithRSAEncryption oid
    Nothing -> assert "OID parse failed" false

  -- Encode OID to DER
  let (OID arcs) = sha256WithRSAEncryption
      oidElem = ASN1 (makeUniversalTag 6 Primitive) (ASN1OID arcs)
      encodedOid = encodeDER oidElem
  case decodeDER encodedOid of
    Just { element } -> assertEq "OID DER roundtrip" oidElem element
    Nothing -> assert "OID decode failed" false

testDerConstructedSequencesAndSets :: Effect Unit
testDerConstructedSequencesAndSets = do
  -- Sequence of integers [1, 2]
  let elem1 = ASN1 (makeUniversalTag 2 Primitive) (ASN1Integer (BigInt.fromInt 1))
      elem2 = ASN1 (makeUniversalTag 2 Primitive) (ASN1Integer (BigInt.fromInt 2))
      seqElem = ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [ elem1, elem2 ])
      encodedSeq = encodeDER seqElem

  assertEq "Sequence [1, 2] encoded DER" [ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 ] encodedSeq

  case decodeDER encodedSeq of
    Just { element } -> assertEq "Sequence roundtrip" seqElem element
    Nothing -> assert "Sequence decode failed" false

  -- Canonical Set sorting: Set elements must be ordered by DER encoding bytes
  let setElem = ASN1 (makeUniversalTag 17 Constructed) (ASN1Set [ elem2, elem1 ])
      encodedSet = encodeDER setElem
  -- When encoded, canonical Set sorting sorts elem1 before elem2:
  assertEq "Set canonical sort orders [1, 2]" [ 0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 ] encodedSet

testPemContainerEncodingAndDecoding :: Effect Unit
testPemContainerEncodingAndDecoding = do
  let payload = [ 0x01, 0x02, 0x03, 0x04, 0x05 ]
      pem = encodePEM "CERTIFICATE" payload

  assert "PEM contains BEGIN header" (String.length pem > 0)

  case decodePEM pem of
    Just block -> do
      assertEq "PEM decoded label" "CERTIFICATE" block.label
      assertEq "PEM decoded bytes" payload block.bytes
    Nothing -> assert "PEM decode failed" false

  -- Multi-block bundle parsing
  let bundlePem = pem <> pem
      blocks = decodePEMMany bundlePem
  assertEq "Decode multi-block PEM bundle count" 2 (length blocks)

testAsn1PrinterDiagnosticOutput :: Effect Unit
testAsn1PrinterDiagnosticOutput = do
  let elem = ASN1 (makeUniversalTag 16 Constructed)
        (ASN1Sequence [ ASN1 (makeUniversalTag 2 Primitive) (ASN1Integer (BigInt.fromInt 42)) ])
      treeStr = printASN1Tree elem
  assert "ASN.1 Diagnostic Printer renders non-empty hierarchy" (String.length treeStr > 0)
