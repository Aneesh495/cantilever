-- | Module: Cantilever.Core.CA.Audit
-- | Description: Cryptographic tamper-evident hash-chained audit logging for CA operations.
-- |
-- | Maintains a sequential hash chain where each event incorporates the previous event digest:
-- | H_i = SHA-256(H_{i-1} || sequence || timestamp || eventType || details)
-- | providing verifiable integrity and non-repudiation across CA lifecycles.

module Cantilever.Core.CA.Audit
  ( ByteArray
  , AuditEventType(..)
  , AuditEvent
  , AuditLog
  , emptyAuditLog
  , appendAuditEvent
  , verifyAuditChain
  , getAuditEntries
  , latestAuditHash
  ) where

import Prelude

import Cantilever.Core.ACME.JWS (stringToUtf8Bytes)
import Cantilever.Core.Crypto.Hash (sha256)
import Data.Array (replicate, uncons)
import Data.Maybe (Maybe(..))

-- | Byte array alias representing octets (0..255).
type ByteArray = Array Int

-- | Supported high-signal audit lifecycle event categories.
data AuditEventType
  = EventInitRoot
  | EventIssueIntermediate
  | EventIssueLeaf
  | EventRevokeCert
  | EventUpdateCRL
  | EventACMEAccountCreated
  | EventACMEOrderFinalized

derive instance eqAuditEventType :: Eq AuditEventType

instance showAuditEventType :: Show AuditEventType where
  show = case _ of
    EventInitRoot -> "INIT_ROOT_CA"
    EventIssueIntermediate -> "ISSUE_INTERMEDIATE_CA"
    EventIssueLeaf -> "ISSUE_LEAF_CERTIFICATE"
    EventRevokeCert -> "REVOKE_CERTIFICATE"
    EventUpdateCRL -> "UPDATE_CRL"
    EventACMEAccountCreated -> "ACME_ACCOUNT_CREATED"
    EventACMEOrderFinalized -> "ACME_ORDER_FINALIZED"

-- | Single immutable entry in the cryptographic audit chain.
type AuditEvent =
  { sequenceNumber :: Int
  , timestamp      :: Int
  , eventType      :: AuditEventType
  , details        :: String
  , previousHash   :: ByteArray
  , entryHash      :: ByteArray
  }

-- | Full tamper-evident audit ledger.
type AuditLog =
  { entries    :: Array AuditEvent
  , latestHash :: ByteArray
  , nextSeq    :: Int
  }

-- | Genesis hash consisting of 32 zero bytes.
genesisHash :: ByteArray
genesisHash = replicate 32 0

-- | Constructs an empty audit ledger initialized at the genesis state.
emptyAuditLog :: AuditLog
emptyAuditLog =
  { entries: []
  , latestHash: genesisHash
  , nextSeq: 1
  }

-- | Encodes an integer into 4 big-endian octets.
encodeInt32 :: Int -> ByteArray
encodeInt32 val =
  let b0 = (val / 16777216) `mod` 256
      b1 = (val / 65536) `mod` 256
      b2 = (val / 256) `mod` 256
      b3 = val `mod` 256
  in [b0, b1, b2, b3]

-- | Computes the SHA-256 entry hash linking to previous block digest.
computeEntryHash :: ByteArray -> Int -> Int -> AuditEventType -> String -> ByteArray
computeEntryHash prevHash seqNum ts evtType details =
  let
    seqBytes = encodeInt32 seqNum
    tsBytes = encodeInt32 ts
    evtBytes = stringToUtf8Bytes (show evtType)
    detailBytes = stringToUtf8Bytes details
    payload = prevHash <> seqBytes <> tsBytes <> evtBytes <> detailBytes
  in
    sha256 payload

-- | Appends a new event to the audit ledger, linking to the preceding hash.
appendAuditEvent :: AuditLog -> AuditEventType -> String -> Int -> AuditLog
appendAuditEvent log evtType details ts =
  let
    prev = log.latestHash
    seq = log.nextSeq
    currHash = computeEntryHash prev seq ts evtType details
    entry :: AuditEvent
    entry =
      { sequenceNumber: seq
      , timestamp: ts
      , eventType: evtType
      , details: details
      , previousHash: prev
      , entryHash: currHash
      }
    updatedEntries = log.entries <> [entry]
  in
    { entries: updatedEntries
    , latestHash: currHash
    , nextSeq: seq + 1
    }

-- | Verifies the cryptographic integrity of the entire audit chain from genesis.
-- | Returns true if all links and internal hashes are mathematically valid.
verifyAuditChain :: AuditLog -> Boolean
verifyAuditChain log =
  loop genesisHash 1 log.entries
  where
  loop _ _ [] = true
  loop expectedPrev expectedSeq entries =
    case uncons entries of
      Nothing -> true
      Just { head: entry, tail: rest } ->
        if entry.previousHash /= expectedPrev then false
        else if entry.sequenceNumber /= expectedSeq then false
        else
          let recomputed = computeEntryHash entry.previousHash entry.sequenceNumber entry.timestamp entry.eventType entry.details
          in
            if entry.entryHash /= recomputed then false
            else loop entry.entryHash (expectedSeq + 1) rest

-- | Returns all entries recorded in the audit ledger.
getAuditEntries :: AuditLog -> Array AuditEvent
getAuditEntries log = log.entries

-- | Returns the latest head hash of the audit chain.
latestAuditHash :: AuditLog -> ByteArray
latestAuditHash log = log.latestHash
