module Cantilever.Core.X509.Types
  ( AlgorithmIdentifier
  , SubjectPublicKeyInfo
  , TBSCertificate
  , Certificate
  , makeAlgorithmIdentifier
  , getCertificateSANs
  , isCertificateCA
  , getCertificateKeyUsage
  , getCertificateSerialNumberHex
  ) where

import Cantilever.Core.ASN1.OID (OID)
import Cantilever.Core.ASN1.Types (ASN1)
import Cantilever.Core.Crypto.BigInt (BigInt, toHexString)
import Cantilever.Core.X509.Extensions
  ( Extension
  , KeyUsageFlag
  , getSanDnsNames
  , hasKeyUsage
  , isCaExtension
  )
import Cantilever.Core.X509.Name (DistinguishedName)
import Cantilever.Core.X509.Validity (Validity)
import Data.Maybe (Maybe(..))

-- | Cryptographic Algorithm Identifier per RFC 5280 Section 4.1.1.2.
type AlgorithmIdentifier =
  { algorithm :: OID
  , parameters :: Maybe ASN1
  }

makeAlgorithmIdentifier :: OID -> AlgorithmIdentifier
makeAlgorithmIdentifier oid =
  { algorithm: oid
  , parameters: Nothing
  }

-- | SubjectPublicKeyInfo representing public key in standard DER format.
type SubjectPublicKeyInfo =
  { algorithm :: AlgorithmIdentifier
  , subjectPublicKey :: Array Int -- raw public key bits
  , rawDer :: Array Int           -- complete SPKI DER sequence
  }

-- | To-Be-Signed Certificate structure per RFC 5280 Section 4.1.2.
type TBSCertificate =
  { version :: Int
  , serialNumber :: BigInt
  , signatureAlgorithm :: AlgorithmIdentifier
  , issuer :: DistinguishedName
  , validity :: Validity
  , subject :: DistinguishedName
  , subjectPublicKeyInfo :: SubjectPublicKeyInfo
  , extensions :: Array Extension
  , rawDer :: Array Int
  }

-- | Complete X.509 v3 Certificate containing signed payload, algorithm, and signature bytes.
type Certificate =
  { tbsCertificate :: TBSCertificate
  , signatureAlgorithm :: AlgorithmIdentifier
  , signatureValue :: Array Int
  , rawDer :: Array Int
  }

-- | Extracts all SAN DNS names from certificate extensions.
getCertificateSANs :: Certificate -> Array String
getCertificateSANs cert = getSanDnsNames cert.tbsCertificate.extensions

-- | Checks if certificate is designated as a Certificate Authority.
isCertificateCA :: Certificate -> Boolean
isCertificateCA cert = isCaExtension cert.tbsCertificate.extensions

-- | Checks if certificate possesses a specific KeyUsage flag.
getCertificateKeyUsage :: KeyUsageFlag -> Certificate -> Boolean
getCertificateKeyUsage flag cert = hasKeyUsage flag cert.tbsCertificate.extensions

-- | Formats certificate serial number as uppercase hex string.
getCertificateSerialNumberHex :: Certificate -> String
getCertificateSerialNumberHex cert = toHexString cert.tbsCertificate.serialNumber
