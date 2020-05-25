-- | Module: Cantilever.Server.Metrics
-- | Description: Prometheus metrics collector and exposition formatter.
-- |
-- | Tracks operational PKI telemetry including certificate issuances, revocations,
-- | OCSP queries, ACME order lifecycles, active nonces, and HTTP traffic.

module Cantilever.Server.Metrics
  ( MetricsState
  , initMetrics
  , incHttpRequests
  , incCertificatesIssued
  , incCertificatesRevoked
  , incOcspRequests
  , incAcmeOrders
  , renderPrometheusMetrics
  ) where

import Prelude

import Data.Array (foldl)
import Data.Map (Map)
import Data.Map as Map
import Data.Maybe (fromMaybe)
import Data.Tuple (Tuple(..))

-- | Internal telemetry counters.
type MetricsState =
  { httpRequestsTotal        :: Map String Int
  , certificatesIssuedTotal  :: Map String Int
  , certificatesRevokedTotal :: Map String Int
  , ocspRequestsTotal        :: Map String Int
  , acmeOrdersTotal          :: Map String Int
  , activeNoncesGauge        :: Int
  , registeredAccountsGauge  :: Int
  }

-- | Initializes zeroed metrics state.
initMetrics :: MetricsState
initMetrics =
  { httpRequestsTotal: Map.empty
  , certificatesIssuedTotal: Map.empty
  , certificatesRevokedTotal: Map.empty
  , ocspRequestsTotal: Map.empty
  , acmeOrdersTotal: Map.empty
  , activeNoncesGauge: 0
  , registeredAccountsGauge: 0
  }

-- | Increments HTTP request counter with label dimensions.
incHttpRequests :: MetricsState -> String -> String -> Int -> MetricsState
incHttpRequests s method path status =
  let key = "method=\"" <> method <> "\",path=\"" <> path <> "\",status=\"" <> show status <> "\""
      cur = fromMaybe 0 (Map.lookup key s.httpRequestsTotal)
      newMap = Map.insert key (cur + 1) s.httpRequestsTotal
  in s { httpRequestsTotal = newMap }

-- | Increments certificate issuance counter.
incCertificatesIssued :: MetricsState -> String -> String -> MetricsState
incCertificatesIssued s caType alg =
  let key = "ca=\"" <> caType <> "\",algorithm=\"" <> alg <> "\""
      cur = fromMaybe 0 (Map.lookup key s.certificatesIssuedTotal)
      newMap = Map.insert key (cur + 1) s.certificatesIssuedTotal
  in s { certificatesIssuedTotal = newMap }

-- | Increments certificate revocation counter.
incCertificatesRevoked :: MetricsState -> String -> MetricsState
incCertificatesRevoked s reason =
  let key = "reason=\"" <> reason <> "\""
      cur = fromMaybe 0 (Map.lookup key s.certificatesRevokedTotal)
      newMap = Map.insert key (cur + 1) s.certificatesRevokedTotal
  in s { certificatesRevokedTotal = newMap }

-- | Increments OCSP query counter.
incOcspRequests :: MetricsState -> String -> MetricsState
incOcspRequests s status =
  let key = "status=\"" <> status <> "\""
      cur = fromMaybe 0 (Map.lookup key s.ocspRequestsTotal)
      newMap = Map.insert key (cur + 1) s.ocspRequestsTotal
  in s { ocspRequestsTotal = newMap }

-- | Increments ACME orders counter.
incAcmeOrders :: MetricsState -> String -> MetricsState
incAcmeOrders s status =
  let key = "status=\"" <> status <> "\""
      cur = fromMaybe 0 (Map.lookup key s.acmeOrdersTotal)
      newMap = Map.insert key (cur + 1) s.acmeOrdersTotal
  in s { acmeOrdersTotal = newMap }

-- | Formats all active metrics into standard Prometheus text exposition format (version 0.0.4).
renderPrometheusMetrics :: MetricsState -> String
renderPrometheusMetrics s =
  let
    header name desc mType =
      "# HELP " <> name <> " " <> desc <> "\n# TYPE " <> name <> " " <> mType <> "\n"

    formatMap metricName m =
      foldl (\acc (Tuple key value) ->
        acc <> metricName <> "{" <> key <> "} " <> show value <> "\n"
      ) "" (Map.toUnfoldable m :: Array (Tuple String Int))

    mHttp = header "cantilever_http_requests_total" "Total number of HTTP requests serviced" "counter"
      <> formatMap "cantilever_http_requests_total" s.httpRequestsTotal

    mIssued = header "cantilever_certificates_issued_total" "Total number of X.509 certificates issued" "counter"
      <> formatMap "cantilever_certificates_issued_total" s.certificatesIssuedTotal

    mRevoked = header "cantilever_certificates_revoked_total" "Total number of X.509 certificates revoked" "counter"
      <> formatMap "cantilever_certificates_revoked_total" s.certificatesRevokedTotal

    mOcsp = header "cantilever_ocsp_requests_total" "Total number of OCSP queries evaluated" "counter"
      <> formatMap "cantilever_ocsp_requests_total" s.ocspRequestsTotal

    mAcme = header "cantilever_acme_orders_total" "Total number of ACME orders processed" "counter"
      <> formatMap "cantilever_acme_orders_total" s.acmeOrdersTotal

    mNonces = header "cantilever_active_nonces" "Currently active valid ACME nonces" "gauge"
      <> "cantilever_active_nonces " <> show s.activeNoncesGauge <> "\n"

    mAccounts = header "cantilever_registered_accounts" "Total registered ACME accounts" "gauge"
      <> "cantilever_registered_accounts " <> show s.registeredAccountsGauge <> "\n"
  in
    mHttp <> "\n" <> mIssued <> "\n" <> mRevoked <> "\n" <> mOcsp <> "\n" <> mAcme <> "\n" <> mNonces <> "\n" <> mAccounts
