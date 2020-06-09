-- | Module: Cantilever.CLI.Args
-- | Description: Command line argument parser for the cantilever administrative CLI.
-- |
-- | Parses CLI subcommands: server, init-ca, validate-path, inspect-cert,
-- | inspect-csr, revoke, bench, and version.

module Cantilever.CLI.Args
  ( CLICommand(..)
  , parseCLIArgs
  , renderUsageHelp
  ) where

import Prelude

import Cantilever.Core.Crypto.BigInt (BigInt)
import Cantilever.Core.Crypto.BigInt as BigInt
import Cantilever.Core.Revocation.Types (CRLReason(..), crlReasonFromInt)
import Data.Array (uncons)
import Data.Int (fromString)
import Data.Maybe (Maybe(..), fromMaybe)

-- | Administrative CLI commands supported by Cantilever.
data CLICommand
  = CmdServer { port :: Int, host :: String }
  | CmdInitCA { rootSubject :: String, interSubject :: String, outDir :: String }
  | CmdValidatePath { trustRoot :: String, leaf :: String, untrusted :: Array String }
  | CmdInspectCert { certPath :: String }
  | CmdInspectCsr { csrPath :: String }
  | CmdRevoke { caKey :: String, caCert :: String, serial :: BigInt, reason :: CRLReason, outCrl :: String }
  | CmdBenchmark { iterations :: Int }
  | CmdVersion
  | CmdHelp (Maybe String)

derive instance eqCLICommand :: Eq CLICommand

-- | Parses raw command-line string arguments.
parseCLIArgs :: Array String -> CLICommand
parseCLIArgs argv =
  case uncons argv of
    Nothing -> CmdHelp Nothing
    Just { head: cmd, tail: rest } ->
      case cmd of
        "server" -> parseServer rest
        "init-ca" -> parseInitCA rest
        "validate-path" -> parseValidate rest
        "inspect-cert" -> parseInspectCert rest
        "inspect-csr" -> parseInspectCsr rest
        "revoke" -> parseRevoke rest
        "bench" -> parseBench rest
        "version" -> CmdVersion
        "--version" -> CmdVersion
        "-v" -> CmdVersion
        "help" -> CmdHelp Nothing
        "--help" -> CmdHelp Nothing
        "-h" -> CmdHelp Nothing
        unknown -> CmdHelp (Just unknown)
  where
  parseServer args =
    let port = fromMaybe 8080 (extractIntFlag "--port" args)
        host = fromMaybe "127.0.0.1" (extractStringFlag "--host" args)
    in CmdServer { port, host }

  parseInitCA args =
    let rootSubj = fromMaybe "CN=Cantilever Global Root CA, O=Cantilever Root PKI, C=US" (extractStringFlag "--root-subject" args)
        interSubj = fromMaybe "CN=Cantilever Authority G1, O=Cantilever Intermediate CA, C=US" (extractStringFlag "--intermediate-subject" args)
        outDir = fromMaybe "./pki" (extractStringFlag "--out-dir" args)
    in CmdInitCA { rootSubject: rootSubj, interSubject: interSubj, outDir }

  parseValidate args =
    case args of
      [root, leaf] -> CmdValidatePath { trustRoot: root, leaf, untrusted: [] }
      [root, leaf, untrusted] -> CmdValidatePath { trustRoot: root, leaf, untrusted: [untrusted] }
      _ -> CmdHelp (Just "validate-path requires <root.pem> <leaf.pem> [intermediate.pem]")

  parseInspectCert args =
    case uncons args of
      Just { head: path } -> CmdInspectCert { certPath: path }
      Nothing -> CmdHelp (Just "inspect-cert requires <cert.pem>")

  parseInspectCsr args =
    case uncons args of
      Just { head: path } -> CmdInspectCsr { csrPath: path }
      Nothing -> CmdHelp (Just "inspect-csr requires <csr.pem>")

  parseRevoke args =
    let mKey = extractStringFlag "--ca-key" args
        mCert = extractStringFlag "--ca-cert" args
        mSerial = extractStringFlag "--serial" args
        mReason = extractIntFlag "--reason" args
        mOut = extractStringFlag "--out-crl" args
    in case mKey, mCert, mSerial of
      Just key, Just cert, Just serialStr ->
        let serial = fromMaybe (BigInt.fromInt 1) (BigInt.fromString serialStr)
            reason = fromMaybe KeyCompromise (mReason >>= crlReasonFromInt)
            outCrl = fromMaybe "./crl.pem" mOut
        in CmdRevoke { caKey: key, caCert: cert, serial, reason, outCrl }
      _, _, _ ->
        CmdHelp (Just "revoke requires --ca-key <path> --ca-cert <path> --serial <hex/dec>")

  parseBench args =
    let iters = fromMaybe 1000 (extractIntFlag "--iterations" args)
    in CmdBenchmark { iterations: iters }

  extractStringFlag flag args =
    case uncons args of
      Nothing -> Nothing
      Just { head: curr, tail: rest } ->
        if curr == flag then
          case uncons rest of
            Just { head: val } -> Just val
            Nothing -> Nothing
        else
          extractStringFlag flag rest

  extractIntFlag flag args =
    case extractStringFlag flag args of
      Just s -> fromString s
      Nothing -> Nothing

-- | Formats usage help banner.
renderUsageHelp :: Maybe String -> String
renderUsageHelp maybeUnknown =
  let errBanner = case maybeUnknown of
        Just u -> "Error: Unknown or malformed command: '" <> u <> "'\n\n"
        Nothing -> ""
  in
    errBanner <>
    "Cantilever: Automated PKI & ACME v2 Certificate Authority (RFC 8555 / RFC 5280)\n\n" <>
    "Usage: cantilever <command> [options]\n\n" <>
    "Commands:\n" <>
    "  server         Start automated ACME v2 and OCSP/CRL daemon\n" <>
    "                 [--port <8080>] [--host <127.0.0.1>]\n\n" <>
    "  init-ca        Generate self-signed Root and delegated Intermediate CA keys and certificates\n" <>
    "                 [--root-subject <DN>] [--intermediate-subject <DN>] [--out-dir <./pki>]\n\n" <>
    "  validate-path  Verify complete RFC 5280 X.509 certification path\n" <>
    "                 <root.pem> <leaf.pem> [intermediate.pem]\n\n" <>
    "  inspect-cert   Decode and display ASN.1 syntax tree and X.509 extensions for certificate\n" <>
    "                 <cert.pem>\n\n" <>
    "  inspect-csr    Verify PKCS#10 proof of possession and dump requested SANs\n" <>
    "                 <csr.pem>\n\n" <>
    "  revoke         Revoke certificate serial number and issue signed CRL\n" <>
    "                 --ca-key <key.pem> --ca-cert <cert.pem> --serial <num> [--reason <code>]\n\n" <>
    "  bench          Run cryptographic microbenchmarks (DER codec, BigInt powMod, GF256, Merkle)\n" <>
    "                 [--iterations <1000>]\n\n" <>
    "  version        Display version and runtime information\n"
