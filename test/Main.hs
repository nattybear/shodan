{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import           Control.Exception        (AsyncException (..), throwIO, try)
import           Control.Monad            (unless)
import           Data.Aeson               (Result (..), Value (..),
                                           eitherDecode', encode, fromJSON,
                                           object, (.=))
import qualified Data.Aeson.KeyMap        as KeyMap
import qualified Data.ByteString.Lazy     as Lazy
import qualified Data.Map.Strict          as Map
import qualified Data.Text                as Text
import qualified Data.Text.Encoding       as TextEncoding
import qualified Network.HTTP.Client      as HTTP
import qualified Network.HTTP.Types       as HTTPTypes
import qualified Network.Wai              as Wai
import           Network.Wai.Handler.Warp (testWithApplication)
import           Shodan

main :: IO ()
main = do
  let expected = ApiInfo 100000 (UsageLimits (-1) (-1) (-1))
        "stream-100" False True 100000 19 100000 False
  case fromJSON example of
    Success actual -> check "official example" (actual == expected)
    Error message  -> fail message
  case fromJSON (change (KeyMap.insert "future_field" Null)) of
    Success actual -> check "unknown fields" (actual == expected)
    Error message  -> fail message
  rejects "missing plan" (change (KeyMap.delete "plan"))
  rejects "null credits" (change (KeyMap.insert "query_credits" Null))
  rejects "wrong boolean type" (change (KeyMap.insert "https" (String "false")))
  rejects "fractional credits" (change (KeyMap.insert "scan_credits" (Number 1.5)))
  rejects "invalid nested limits" (change (KeyMap.insert "usage_limits" (object [])))
  rejects "non-object response" (Array mempty)
  facetTests
  countParsingTests
  httpTests
  countTests
  putStrLn "All response parsing and HTTP tests passed."

facetTests :: IO ()
facetTests = do
  -- The organization bucket is from the official count endpoint example.
  let cases =
        [ ("official facet", "{\"value\":\"Amazon.com\",\"count\":3012386}",
            Facet (String "Amazon.com") 3012386)
        , ("numeric value", "{\"value\":443,\"count\":12}", Facet (Number 443) 12)
        , ("explicit null value", "{\"value\":null,\"count\":2}", Facet Null 2)
        , ("zero count", "{\"value\":\"KR\",\"count\":0}", Facet (String "KR") 0)
        , ("large count", "{\"value\":\"KR\",\"count\":100000000000000000000}",
            Facet (String "KR") 100000000000000000000)
        , ("unknown field", "{\"value\":\"KR\",\"count\":1,\"future\":true}",
            Facet (String "KR") 1)
        , ("null value preserved", "{\"value\":null,\"count\":1}", Facet Null 1)
        ]
  mapM_ (\(label, body, expected) ->
    check label (eitherDecode' body == Right expected)) cases
  let invalidCases =
        [ ("missing value", "{\"count\":1}")
        , ("missing count", "{\"value\":\"KR\"}")
        , ("null count", "{\"value\":\"KR\",\"count\":null}")
        , ("string count", "{\"value\":\"KR\",\"count\":\"1\"}")
        , ("fractional count", "{\"value\":\"KR\",\"count\":1.5}")
        , ("negative count", "{\"value\":\"KR\",\"count\":-1}")
        , ("non-object facet", "[]")
        , ("malformed facet JSON", "not JSON")
        , ("negative count", "{\"value\":\"KR\",\"count\":-1}")
        , ("non-object facet", "[]")
        , ("malformed facet", "not JSON")
        ]
  mapM_ (\(label, body) -> case eitherDecode' body :: Either String Facet of
    Left _  -> pure ()
    Right _ -> fail (label ++ ": unexpectedly accepted")) invalidCases
  let buckets = "[{\"value\":\"US\",\"count\":2},{\"value\":\"KR\",\"count\":1}]"
  check "facet list" (eitherDecode' buckets ==
    Right [Facet (String "US") 2, Facet (String "KR") 1])

httpTests :: IO ()
httpTests = do
  let key = "test key+&?=한글"
      application request respond = do
        check "GET method" (Wai.requestMethod request == "GET")
        check "request path" (Wai.pathInfo request == ["api-info"])
        check "encoded key" (Wai.queryString request ==
          [("key", Just (TextEncoding.encodeUtf8 key))])
        check "accept header" (lookup "Accept" (Wai.requestHeaders request) ==
          Just "application/json")
        respond (Wai.responseLBS HTTPTypes.status200 [] (encode example))
  withMockClient key application $ \client -> do
    check "client key redacted" (not (key `Text.isInfixOf` Text.pack (show client)))
    result <- getApiInfo client
    check "HTTP success" (result == (case fromJSON example of
      Success info -> Right info
      Error _      -> Left InvalidResponse))
  checkResponse "unauthorized" HTTPTypes.status401 "{\"error\":\"test-key\"}"
    (Left (HttpError 401))
  checkResponse "rate limited" HTTPTypes.status429 "not JSON"
    (Left (HttpError 429))
  checkResponse "server error" HTTPTypes.status500 "<html>unavailable</html>"
    (Left (HttpError 500))
  checkResponse "malformed JSON" HTTPTypes.status200 "not JSON"
    (Left InvalidResponse)
  checkResponse "wrong response shape" HTTPTypes.status200 "{}"
    (Left InvalidResponse)
  checkResponse "unexpected success status" HTTPTypes.status204 ""
    (Left (HttpError 204))
  let redirect _ respond = respond (Wai.responseLBS HTTPTypes.status302
        [("Location", "https://example.invalid/never-follow")] "")
  withMockClient "test-key" redirect $ \client -> do
    result <- getApiInfo client
    check "redirect not followed" (result == Left (HttpError 302))
  -- Inject an http-client transport exception without relying on external DNS.
  manager <- HTTP.newManager HTTP.defaultManagerSettings
    { HTTP.managerModifyRequest = \request -> throwIO
        (HTTP.HttpExceptionRequest request HTTP.ConnectionTimeout)
    }
  result <- getApiInfo (newClientWithManager manager "test-key")
  check "network failure" (result == Left NetworkError)
  cancellingManager <- HTTP.newManager HTTP.defaultManagerSettings
    { HTTP.managerModifyRequest = \_ -> throwIO ThreadKilled }
  cancelled <- try (getApiInfo (newClientWithManager cancellingManager "test-key"))
    :: IO (Either AsyncException (Either ShodanError ApiInfo))
  check "thread cancellation propagates" (cancelled == Left ThreadKilled)

countParsingTests :: IO ()
countParsingTests = do
  let country = [Facet (String "KR") 60, Facet (String "US") 40]
      expected = CountResult 100 (Map.fromList
        [("country", country), ("port", [Facet (Number 443) 80])])
      response = "{\"total\":100,\"facets\":{\"country\":[{\"value\":\"KR\",\"count\":60},{\"value\":\"US\",\"count\":40}],\"port\":[{\"value\":443,\"count\":80}]},\"matches\":[]}"
  check "count grouped facets" (eitherDecode' response == Right expected)
  check "count absent facets" (eitherDecode' "{\"total\":100}" ==
    Right (CountResult 100 Map.empty))
  check "count empty facets" (eitherDecode' "{\"total\":0,\"facets\":{}}" ==
    Right (CountResult 0 Map.empty))
  check "count empty bucket list" (eitherDecode'
    "{\"total\":0,\"facets\":{\"country\":[]}}" ==
    Right (CountResult 0 (Map.singleton "country" [])))
  mapM_ (\(label, body) -> case eitherDecode' body :: Either String CountResult of
    Left _  -> pure ()
    Right _ -> fail label)
    [ ("null facets", "{\"total\":1,\"facets\":null}")
    , ("array facets", "{\"total\":1,\"facets\":[]}")
    , ("non-list buckets", "{\"total\":1,\"facets\":{\"country\":{}}}")
    , ("null buckets", "{\"total\":1,\"facets\":{\"country\":null}}")
    , ("missing bucket count", "{\"total\":1,\"facets\":{\"country\":[{\"value\":\"KR\"}]}}")
    , ("negative bucket count", "{\"total\":1,\"facets\":{\"port\":[{\"value\":443,\"count\":-1}]}}")
    ]

countTests :: IO ()
countTests = do
  let key = "count-test-key"
      query = "http.title:\"한글 + & ?\" country:KR"
      application request respond = do
        check "count GET" (Wai.requestMethod request == "GET")
        check "count path" (Wai.pathInfo request == ["shodan", "host", "count"])
        check "count query encoding" (Wai.queryString request ==
          [("key", Just (TextEncoding.encodeUtf8 key)),
           ("query", Just (TextEncoding.encodeUtf8 query))])
        respond (Wai.responseLBS HTTPTypes.status200 []
          "{\"total\":19592093,\"matches\":[]}")
  withMockClient key application $ \client -> do
    actual <- countHosts client query
    check "count success" (actual == Right (CountResult 19592093 Map.empty))
  countResponse "zero count" HTTPTypes.status200 "{\"total\":0}"
    (Right (CountResult 0 Map.empty))
  countResponse "large count and unknown fields" HTTPTypes.status200
    "{\"total\":100000000000000000000,\"facets\":{},\"future\":true}"
    (Right (CountResult 100000000000000000000 Map.empty))
  mapM_ (\body -> countResponse "invalid count" HTTPTypes.status200 body
    (Left InvalidResponse))
    [ "{}", "{\"total\":null}", "{\"total\":\"12\"}"
    , "{\"total\":1.5}", "{\"total\":-1}", "[]", "invalid JSON"
    ]
  countResponse "count unauthorized" HTTPTypes.status401 "{\"error\":\"Invalid key\"}"
    (Left (HttpError 401))
  countResponse "count rate limited" HTTPTypes.status429 "not JSON"
    (Left (HttpError 429))

countResponse :: String -> HTTPTypes.Status -> Lazy.ByteString
  -> Either ShodanError CountResult -> IO ()
countResponse label status body expected = do
  let application _ respond = respond (Wai.responseLBS status [] body)
  withMockClient "count-test-key" application $ \client -> do
    actual <- countHosts client "port:443"
    check label (actual == expected)

checkResponse :: String -> HTTPTypes.Status -> Lazy.ByteString
  -> Either ShodanError ApiInfo -> IO ()
checkResponse label status body expected = do
  let application _ respond = respond (Wai.responseLBS status [] body)
  withMockClient "test-key" application $ \client -> do
    actual <- getApiInfo client
    check label (actual == expected)

-- Redirect only the test transport to a local server; production always uses
-- the fixed HTTPS endpoint. Validate the original destination before rewriting.
withMockClient :: Text.Text -> Wai.Application -> (Client -> IO ()) -> IO ()
withMockClient key application run = testWithApplication (pure application) $ \port -> do
  manager <- HTTP.newManager HTTP.defaultManagerSettings
    { HTTP.managerModifyRequest = \request -> do
        check "finite timeout" (HTTP.responseTimeout request ==
          HTTP.responseTimeoutMicro 30000000)
        -- http-client can apply the hook more than once to the same request.
        if not (HTTP.secure request) && HTTP.host request == "127.0.0.1"
            && HTTP.port request == port
          then pure request
          else do
            check "HTTPS endpoint" (HTTP.secure request &&
              HTTP.host request == "api.shodan.io" && HTTP.port request == 443)
            pure request
              { HTTP.secure = False
              , HTTP.host = "127.0.0.1"
              , HTTP.port = port
              , HTTP.proxy = Nothing
              }
    }
  run (newClientWithManager manager key)

check :: String -> Bool -> IO ()
check label passed = unless passed (fail label)

rejects :: String -> Value -> IO ()
rejects label value = case fromJSON value :: Result ApiInfo of
  Error _   -> pure ()
  Success _ -> fail (label ++ ": unexpectedly accepted")

change :: (KeyMap.KeyMap Value -> KeyMap.KeyMap Value) -> Value
change f = case example of
  Object o -> Object (f o)
  _        -> example

-- Source: https://developer.shodan.io/api, GET /api-info response example.
example :: Value
example = object
  [ "scan_credits" .= (100000 :: Integer)
  , "usage_limits" .= object
      [ "scan_credits" .= (-1 :: Integer)
      , "query_credits" .= (-1 :: Integer)
      , "monitored_ips" .= (-1 :: Integer)
      ]
  , "plan" .= String "stream-100"
  , "https" .= False
  , "unlocked" .= True
  , "query_credits" .= (100000 :: Integer)
  , "monitored_ips" .= (19 :: Integer)
  , "unlocked_left" .= (100000 :: Integer)
  , "telnet" .= False
  ]
