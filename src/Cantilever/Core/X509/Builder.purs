module Cantilever.Core.X509.Builder
  ( buildTBSCertificateAst
  , encodeCertificateDER
  , signCertificate
  , buildSelfSignedRootCA
  , buildIntermediateCA
  , buildEndEntityCertificate
  ) where

import Prelude

import Cantilever.Core.ASN1.DER (encodeDER)
import Cantilever.Core.ASN1.OID
  ( OID(..)
  , ekuServerAuth
  , extAuthorityKeyIdentifier
  , extBasicConstraints
  , extExtKeyUsage
  , extKeyUsage
  , extSubjectAltName
  , extSubjectKeyIdentifier
  , sha256WithRSAEncryption
  )
import Cantilever.Core.ASN1.Types
  ( ASN1(..)
  , ASN1Tag(..)
  , ASN1Value(..)
  , TagClass(..)
  , TagForm(..)
  , makeUniversalTag
  )
import Cantilever.Core.Crypto.BigInt (BigInt, fromInt)
import Cantilever.Core.Crypto.Hash (sha256)
import Cantilever.Core.Crypto.Key (KeyPair, PrivateKey, PublicKey)
import Cantilever.Core.Crypto.Signature (SignatureAlgorithm(..), signData)
import Cantilever.Core.X509.Extensions
  ( ExtensionValue(..)
  , GeneralName(..)
  , KeyUsageFlag(..)
  , encodeExtensionAst
  )
import Cantilever.Core.X509.Name (DistinguishedName, encodeDNAst)
import Cantilever.Core.X509.Types (AlgorithmIdentifier, Certificate, SubjectPublicKeyInfo, TBSCertificate, makeAlgorithmIdentifier)
import Cantilever.Core.X509.Validity (encodeValidityAst, makeValidity)
import Data.Maybe (Maybe(..))

-- | Converts TBSCertificate into an ASN.1 Structure according to RFC 5280 Section 4.1.2.
buildTBSCertificateAst :: TBSCertificate -> ASN1
buildTBSCertificateAst tbs =
  let
    seqTag = makeUniversalTag 16 Constructed

    -- Version 3 is encoded as [0] EXPLICIT INTEGER 2
    versionAst = ASN1 (ASN1Tag { tagClass: ContextSpecific, tagForm: Constructed, tagNumber: 0 })
      (ASN1Sequence [ ASN1 (makeUniversalTag 2 Primitive) (ASN1Integer (fromInt tbs.version)) ])

    serialAst = ASN1 (makeUniversalTag 2 Primitive) (ASN1Integer tbs.serialNumber)
    sigAlgAst = encodeAlgorithmIdAst tbs.signatureAlgorithm
    issuerAst = encodeDNAst tbs.issuer
    validityAst = encodeValidityAst tbs.validity
    subjectAst = encodeDNAst tbs.subject
    spkiAst = encodeSpkiAst tbs.subjectPublicKeyInfo

    extSeqAst = ASN1 (makeUniversalTag 16 Constructed)
      (tbs.extensions <#> encodeExtensionAst # ASN1Sequence)
    extContainerAst = ASN1 (ASN1Tag { tagClass: ContextSpecific, tagForm: Constructed, tagNumber: 3 })
      (ASN1Sequence [ extSeqAst ])

    elements =
      [ versionAst
      , serialAst
      , sigAlgAst
      , issuerAst
      , validityAst
      , subjectAst
      , spkiAst
      , extContainerAst
      ]
  in
    ASN1 seqTag (ASN1Sequence elements)

-- | Encodes an AlgorithmIdentifier into ASN.1.
encodeAlgorithmIdAst :: AlgorithmIdentifier -> ASN1
encodeAlgorithmIdAst alg =
  let
    (OID arcs) = alg.algorithm
    oidAst = ASN1 (makeUniversalTag 6 Primitive) (ASN1OID arcs)
    nullAst = ASN1 (makeUniversalTag 5 Primitive) ASN1Null
  in
    ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [ oidAst, nullAst ])

-- | Encodes SubjectPublicKeyInfo into ASN.1.
encodeSpkiAst :: SubjectPublicKeyInfo -> ASN1
encodeSpkiAst spki =
  let
    algAst = encodeAlgorithmIdAst spki.algorithm
    bitStringAst = ASN1 (makeUniversalTag 3 Primitive) (ASN1BitString 0 spki.subjectPublicKey)
  in
    ASN1 (makeUniversalTag 16 Constructed) (ASN1Sequence [ algAst, bitStringAst ])

-- | Encodes a complete Certificate into DER bytes.
encodeCertificateDER :: Certificate -> Array Int
encodeCertificateDER cert =
  let
    tbsAst = buildTBSCertificateAst cert.tbsCertificate
    sigAlgAst = encodeAlgorithmIdAst cert.signatureAlgorithm
    sigBitsAst = ASN1 (makeUniversalTag 3 Primitive) (ASN1BitString 0 cert.signatureValue)
    certAst = ASN1 (makeUniversalTag 16 Constructed)
      (ASN1Sequence [ tbsAst, sigAlgAst, sigBitsAst ])
  in
    encodeDER certAst

-- | Signs a TBSCertificate using a PrivateKey and SignatureAlgorithm.
signCertificate :: SignatureAlgorithm -> PrivateKey -> TBSCertificate -> Maybe Certificate
signCertificate sigAlg privKey tbs = do
  let
    tbsAst = buildTBSCertificateAst tbs
    tbsDer = encodeDER tbsAst
  sigBytes <- signData sigAlg privKey tbsDer
  let
    certTbs = tbs { rawDer = tbsDer }
    cert =
      { tbsCertificate: certTbs
      , signatureAlgorithm: tbs.signatureAlgorithm
      , signatureValue: sigBytes
      , rawDer: []
      }
    fullDer = encodeCertificateDER cert
  Just (cert { rawDer = fullDer })

-- | Extracts SubjectPublicKeyInfo from a PublicKey.
extractSpki :: PublicKey -> SubjectPublicKeyInfo
extractSpki pubKey =
  { algorithm: makeAlgorithmIdentifier sha256WithRSAEncryption
  , subjectPublicKey: pubKey.rawSpki
  , rawDer: pubKey.rawSpki
  }

-- | Builds a self-signed Root CA certificate with basicConstraints(isCA=true) and keyCertSign.
buildSelfSignedRootCA
  :: DistinguishedName
  -> BigInt
  -> Int
  -> KeyPair
  -> Maybe Certificate
buildSelfSignedRootCA subject serial durationDays keyPair =
  let
    validity = makeValidity 0 durationDays
    pubKeyHash = sha256 keyPair.publicKey.rawSpki

    extensions =
      [ { oid: extBasicConstraints
        , critical: true
        , value: BasicConstraints { isCA: true, pathLenConstraint: Nothing }
        }
      , { oid: extKeyUsage
        , critical: true
        , value: KeyUsage [ KeyCertSign, CRLSign, DigitalSignature ]
        }
      , { oid: extSubjectKeyIdentifier
        , critical: false
        , value: SubjectKeyIdentifier pubKeyHash
        }
      , { oid: extAuthorityKeyIdentifier
        , critical: false
        , value: AuthorityKeyIdentifier { keyIdentifier: Just pubKeyHash, authorityCertSerialNumber: Just serial }
        }
      ]

    tbs :: TBSCertificate
    tbs =
      { version: 2 -- X.509 v3
      , serialNumber: serial
      , signatureAlgorithm: makeAlgorithmIdentifier sha256WithRSAEncryption
      , issuer: subject
      , validity: validity
      , subject: subject
      , subjectPublicKeyInfo: extractSpki keyPair.publicKey
      , extensions: extensions
      , rawDer: []
      }
  in
    signCertificate RsaSha256 keyPair.privateKey tbs

-- | Builds an Intermediate CA certificate signed by an issuing parent CA.
buildIntermediateCA
  :: Certificate
  -> PrivateKey
  -> DistinguishedName
  -> BigInt
  -> Int
  -> Maybe Int
  -> KeyPair
  -> Maybe Certificate
buildIntermediateCA parentCert parentPrivKey subject serial durationDays mPathLen keyPair =
  let
    validity = makeValidity 0 durationDays
    pubKeyHash = sha256 keyPair.publicKey.rawSpki
    parentKeyHash = sha256 parentCert.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey

    extensions =
      [ { oid: extBasicConstraints
        , critical: true
        , value: BasicConstraints { isCA: true, pathLenConstraint: mPathLen }
        }
      , { oid: extKeyUsage
        , critical: true
        , value: KeyUsage [ KeyCertSign, CRLSign, DigitalSignature ]
        }
      , { oid: extSubjectKeyIdentifier
        , critical: false
        , value: SubjectKeyIdentifier pubKeyHash
        }
      , { oid: extAuthorityKeyIdentifier
        , critical: false
        , value: AuthorityKeyIdentifier
            { keyIdentifier: Just parentKeyHash
            , authorityCertSerialNumber: Just parentCert.tbsCertificate.serialNumber
            }
        }
      ]

    tbs :: TBSCertificate
    tbs =
      { version: 2
      , serialNumber: serial
      , signatureAlgorithm: parentCert.signatureAlgorithm
      , issuer: parentCert.tbsCertificate.subject
      , validity: validity
      , subject: subject
      , subjectPublicKeyInfo: extractSpki keyPair.publicKey
      , extensions: extensions
      , rawDer: []
      }
  in
    signCertificate RsaSha256 parentPrivKey tbs

-- | Builds an End-Entity (leaf TLS server) certificate signed by an intermediate CA.
buildEndEntityCertificate
  :: Certificate
  -> PrivateKey
  -> DistinguishedName
  -> Array String
  -> BigInt
  -> Int
  -> PublicKey
  -> Maybe Certificate
buildEndEntityCertificate issuerCert issuerPrivKey subject sans serial durationDays pubKey =
  let
    validity = makeValidity 0 durationDays
    pubKeyHash = sha256 pubKey.rawSpki
    issuerKeyHash = sha256 issuerCert.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey
    sanGeneralNames = sans <#> DnsName

    extensions =
      [ { oid: extBasicConstraints
        , critical: true
        , value: BasicConstraints { isCA: false, pathLenConstraint: Nothing }
        }
      , { oid: extKeyUsage
        , critical: true
        , value: KeyUsage [ DigitalSignature, KeyEncipherment ]
        }
      , { oid: extExtKeyUsage
        , critical: false
        , value: ExtKeyUsage [ ekuServerAuth ]
        }
      , { oid: extSubjectAltName
        , critical: false
        , value: SubjectAltName sanGeneralNames
        }
      , { oid: extSubjectKeyIdentifier
        , critical: false
        , value: SubjectKeyIdentifier pubKeyHash
        }
      , { oid: extAuthorityKeyIdentifier
        , critical: false
        , value: AuthorityKeyIdentifier
            { keyIdentifier: Just issuerKeyHash
            , authorityCertSerialNumber: Just issuerCert.tbsCertificate.serialNumber
            }
        }
      ]

    tbs :: TBSCertificate
    tbs =
      { version: 2
      , serialNumber: serial
      , signatureAlgorithm: issuerCert.signatureAlgorithm
      , issuer: issuerCert.tbsCertificate.subject
      , validity: validity
      , subject: subject
      , subjectPublicKeyInfo: extractSpki pubKey
      , extensions: extensions
      , rawDer: []
      }
  in
    signCertificate RsaSha256 issuerPrivKey tbs
