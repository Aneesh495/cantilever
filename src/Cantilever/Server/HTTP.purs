-- | Module: Cantilever.Server.HTTP
-- | Description: Native HTTP server bindings and request/response dispatch pipeline.
-- |
-- | Integrates Node.js HTTP server primitives via FFI, providing structured
-- | representations for HTTP methods, headers, binary payloads, and status codes.

module Cantilever.Server.HTTP
  ( Header
  , HttpRequest
  , HttpResponse
  , ServerConfig
  , defaultResponse
  , jsonResponse
  , problemResponse
  , textResponse
  , derResponse
  , pemResponse
  , getHeader
  , startHttpServer
  ) where

import Prelude

import Cantilever.Core.ACME.Types (ProblemDocument, problemTypeUrn)
import Data.Array (filter, head)
import Data.Maybe (Maybe)
import Data.String.Common (toLower)
import Effect (Effect)

-- | Key-value HTTP header.
type Header =
  { key   :: String
  , value :: String
  }

-- | Request payload received from client.
type HttpRequest =
  { method    :: String
  , url       :: String
  , headers   :: Array Header
  , bodyText  :: String
  , bodyBytes :: Array Int
  }

-- | Response payload to return to client.
type HttpResponse =
  { statusCode :: Int
  , headers    :: Array Header
  , bodyText   :: String
  , bodyBytes  :: Array Int
  }

-- | Server configuration options.
type ServerConfig =
  { host    :: String
  , port    :: Int
  , handler :: HttpRequest -> (HttpResponse -> Effect Unit) -> Effect Unit
  }

-- | Foreign JS runner starting the HTTP daemon.
foreign import startHttpServerRaw :: ServerConfig -> Effect (Effect Unit)

-- | Starts an HTTP server and returns an Effect action to stop it.
startHttpServer :: ServerConfig -> Effect (Effect Unit)
startHttpServer = startHttpServerRaw

-- | Retrieves a header value case-insensitively from an HttpRequest.
getHeader :: String -> HttpRequest -> Maybe String
getHeader name req =
  let target = toLower name
      matches = filter (\h -> toLower h.key == target) req.headers
  in map _.value (head matches)

-- | Default empty 200 OK response.
defaultResponse :: HttpResponse
defaultResponse =
  { statusCode: 200
  , headers: []
  , bodyText: ""
  , bodyBytes: []
  }

-- | Constructs a JSON response with standard CORS headers.
jsonResponse :: Int -> String -> HttpResponse
jsonResponse code jsonBody =
  { statusCode: code
  , headers:
      [ { key: "Content-Type", value: "application/json; charset=utf-8" }
      , { key: "Access-Control-Allow-Origin", value: "*" }
      , { key: "Access-Control-Allow-Methods", value: "GET, POST, HEAD, OPTIONS" }
      , { key: "Access-Control-Allow-Headers", value: "Content-Type, Replay-Nonce" }
      ]
  , bodyText: jsonBody
  , bodyBytes: []
  }

-- | Constructs an RFC 7807 / RFC 8555 application/problem+json response.
problemResponse :: ProblemDocument -> HttpResponse
problemResponse prob =
  let
    urn = problemTypeUrn prob.problemType
    jsonBody =
      "{\"type\":\"" <> urn <> "\",\"title\":\"" <> prob.title <> "\",\"status\":" <> show prob.status <> ",\"detail\":\"" <> prob.detail <> "\"}"
  in
    { statusCode: prob.status
    , headers:
        [ { key: "Content-Type", value: "application/problem+json; charset=utf-8" }
        , { key: "Access-Control-Allow-Origin", value: "*" }
        ]
    , bodyText: jsonBody
    , bodyBytes: []
    }

-- | Constructs a plain text response.
textResponse :: Int -> String -> HttpResponse
textResponse code text =
  { statusCode: code
  , headers:
      [ { key: "Content-Type", value: "text/plain; charset=utf-8" }
      , { key: "Access-Control-Allow-Origin", value: "*" }
      ]
  , bodyText: text
  , bodyBytes: []
  }

-- | Constructs a binary application/pkix-crl or application/ocsp-response DER response.
derResponse :: Int -> String -> Array Int -> HttpResponse
derResponse code contentType bytes =
  { statusCode: code
  , headers:
      [ { key: "Content-Type", value: contentType }
      , { key: "Access-Control-Allow-Origin", value: "*" }
      ]
  , bodyText: ""
  , bodyBytes: bytes
  }

-- | Constructs an application/pem-certificate-chain response.
pemResponse :: Int -> String -> HttpResponse
pemResponse code pemChain =
  { statusCode: code
  , headers:
      [ { key: "Content-Type", value: "application/pem-certificate-chain" }
      , { key: "Access-Control-Allow-Origin", value: "*" }
      ]
  , bodyText: pemChain
  , bodyBytes: []
  }
