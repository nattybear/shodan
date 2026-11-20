{-# LANGUAGE OverloadedStrings #-}

-- | A small client for the Shodan API.
module Shodan
  ( Client
  , newClient
  , newClientWithManager
  , ShodanError (..)
  , getApiInfo
  , countHosts
  , searchHosts
  , CountResult (..)
  , Facet (..)
  , SearchMatch (..)
  , SearchResult (..)
  , ApiInfo (..)
  , UsageLimits (..)
  ) where

import           Control.Exception       (catch)
import           Data.Aeson              (FromJSON (..), Value, eitherDecode',
                                          withObject, (.!=), (.:!), (.:), (.:?))
import           Data.Map.Strict         (Map)
import qualified Data.Map.Strict         as Map
import           Data.Text               (Text)
import qualified Data.Text               as DataText
import qualified Data.Text.Encoding      as Text
import qualified Network.HTTP.Client     as HTTP
import           Network.HTTP.Client.TLS (tlsManagerSettings)
import           Network.HTTP.Types      (statusCode)

-- | Reuse one client across requests. Its API key is never included in 'show'.
data Client = Client HTTP.Manager Text

instance Show Client where
  show _ = "Client <redacted>"

-- | Create a client with certificate-verified HTTPS connections.
-- Pass the key from configuration or an environment variable, not a source file.
newClient :: Text -> IO Client
newClient key = do
  manager <- HTTP.newManager tlsManagerSettings
  pure (newClientWithManager manager key)

-- | Share an existing manager. It must support TLS for production use.
-- Custom manager hooks can inspect requests, including the key: do not log them.
newClientWithManager :: HTTP.Manager -> Text -> Client
newClientWithManager = Client

-- | Failures deliberately omit raw requests, response bodies, and exception
-- messages, since those may contain the API key. HTTP errors retain the status.
data ShodanError
  = NetworkError
  | HttpError Int
  | InvalidResponse
  | InvalidPage
    -- ^ Search page numbers must be at least 1. No request was made.
  deriving (Eq, Show)

-- | Retrieve @GET https://api.shodan.io/api-info@.
-- No automatic retries are performed. Redirects are returned as HTTP errors
-- rather than followed, so the key is not forwarded to another endpoint.
-- Transport failures (including timeouts) become 'NetworkError'; asynchronous
-- exceptions, such as thread cancellation, are not caught.
getApiInfo :: Client -> IO (Either ShodanError ApiInfo)
getApiInfo client = getJSON client "/api-info" []

-- | Count matching results without downloading individual banners.
-- Optional facets are not requested, but any returned facets are decoded.
-- According to Shodan's documentation this endpoint uses no query credits.
countHosts :: Client -> Text -> IO (Either ShodanError CountResult)
countHosts client query = getJSON client "/shodan/host/count" [("query", query)]

-- | Retrieve one page from @GET /shodan/host/search@.
-- The page number starts at 1. No additional pages are fetched automatically.
-- Filtered queries and requests after page 1 use query credits. Requests past
-- page 100 must be made in order, as required by Shodan. Optional facets and
-- field selection are not requested.
searchHosts :: Client -> Text -> Int -> IO (Either ShodanError SearchResult)
searchHosts client query page
  | page < 1 = pure (Left InvalidPage)
  | otherwise = getJSON client "/shodan/host/search"
      [("query", query), ("page", DataText.pack (show page))]

-- | Total matching results and optional breakdowns from @GET /shodan/host/count@.
data CountResult = CountResult
  { countTotal  :: Integer
    -- ^ Total number of matching results; must be nonnegative.
  , countFacets :: Map Text [Facet]
    -- ^ Buckets by facet name, for example @country@ or @port@.
    -- An absent @facets@ field is read as an empty map. A present field must
    -- be an object of bucket lists; @null@ and malformed entries are rejected.
  } deriving (Eq, Show)

instance FromJSON CountResult where
  parseJSON = withObject "CountResult" $ \o -> do
    total <- o .: "total"
    facets <- o .:! "facets" .!= Map.empty
    if total < 0
      then fail "Count total must not be negative"
      else pure (CountResult total facets)

-- | One bucket in a facet breakdown, for example
-- @{"value":"Amazon.com","count":3012386}@.
-- The value is kept as JSON because facet values need not all be strings
-- (a port number, for example, is numeric). Both fields are required;
-- unknown fields are ignored. HTTP facet requests are not supported yet.
data Facet = Facet
  { facetValue :: Value
    -- ^ The bucket value, preserved without converting it to text.
  , facetCount :: Integer
    -- ^ Number of matching results in the bucket; must be nonnegative.
  } deriving (Eq, Show)

instance FromJSON Facet where
  parseJSON = withObject "Facet" $ \o -> do
    value <- o .: "value"
    count <- o .: "count"
    if count < 0
      then fail "Facet count must not be negative"
      else pure (Facet value count)

-- | One matching service in a search response, rather than a unique host.
-- Unmodelled banner fields are ignored. The IP address is preserved as text;
-- its syntax is not validated here.
data SearchMatch = SearchMatch
  { matchIp      :: Text
    -- ^ Required @ip_str@ field, usable for IPv4 or IPv6 text.
  , matchPort    :: Int
    -- ^ Required integer port, from 0 through 65535.
  , matchProduct :: Maybe Text
    -- ^ Detected product; absent or null means 'Nothing'.
  , matchAsn     :: Maybe Text
    -- ^ ASN such as @AS65536@; absent or null means 'Nothing'.
  } deriving (Eq, Show)

instance FromJSON SearchMatch where
  parseJSON = withObject "SearchMatch" $ \o -> do
    ip <- o .: "ip_str"
    port <- o .: "port"
    productName <- o .:? "product"
    asn <- o .:? "asn"
    if port < 0 || port > 65535
      then fail "Search match port must be between 0 and 65535"
      else pure (SearchMatch ip port productName asn)

-- | One page returned by @GET /shodan/host/search@.
-- The total covers the whole query and may exceed this page's match count.
data SearchResult = SearchResult
  { searchTotal   :: Integer
    -- ^ Required nonnegative total across all pages.
  , searchMatches :: [SearchMatch]
    -- ^ Required service list; an empty page is valid. Order is preserved.
  , searchFacets  :: Map Text [Facet]
    -- ^ Optional breakdowns. Missing means an empty map; null is rejected.
  } deriving (Eq, Show)

instance FromJSON SearchResult where
  parseJSON = withObject "SearchResult" $ \o -> do
    total <- o .: "total"
    matches <- o .: "matches"
    facets <- o .:! "facets" .!= Map.empty
    if total < 0
      then fail "Search total must not be negative"
      else pure (SearchResult total matches facets)

-- Shared transport keeps status handling and key protection consistent.
getJSON :: FromJSON a => Client -> Text -> [(Text, Text)]
  -> IO (Either ShodanError a)
getJSON (Client manager key) endpoint parameters = action `catch` handleHttpException
  where
    request = HTTP.setQueryString
      [(Text.encodeUtf8 name, Just (Text.encodeUtf8 value))
        | (name, value) <- ("key", key) : parameters]
      HTTP.defaultRequest
        { HTTP.secure = True
        , HTTP.host = "api.shodan.io"
        , HTTP.port = 443
        , HTTP.path = Text.encodeUtf8 endpoint
        , HTTP.requestHeaders = [("Accept", "application/json")]
        , HTTP.redirectCount = 0
        , HTTP.responseTimeout = HTTP.responseTimeoutMicro 30000000
        , HTTP.checkResponse = \_ _ -> pure ()
        }
    action = do
      response <- HTTP.httpLbs request manager
      let status = statusCode (HTTP.responseStatus response)
      pure $ if status /= 200
        then Left (HttpError status)
        else case eitherDecode' (HTTP.responseBody response) of
          Left _     -> Left InvalidResponse
          Right info -> Right info

handleHttpException :: HTTP.HttpException -> IO (Either ShodanError a)
handleHttpException _ = pure (Left NetworkError)

-- | API plan information returned by @GET /api-info@.
-- Fields follow the official response example; extra JSON fields are ignored.
data ApiInfo = ApiInfo
  { apiInfoScanCredits  :: Integer
  , apiInfoUsageLimits  :: UsageLimits
  , apiInfoPlan         :: Text
  , apiInfoHttps        :: Bool
  , apiInfoUnlocked     :: Bool
  , apiInfoQueryCredits :: Integer
  , apiInfoMonitoredIps :: Integer
  , apiInfoUnlockedLeft :: Integer
  , apiInfoTelnet       :: Bool
  } deriving (Eq, Show)

-- | Usage limits as returned by Shodan, including signed values such as @-1@.
-- Values are preserved without assigning undocumented meanings to them.
data UsageLimits = UsageLimits
  { usageLimitsScanCredits  :: Integer
  , usageLimitsQueryCredits :: Integer
  , usageLimitsMonitoredIps :: Integer
  } deriving (Eq, Show)

instance FromJSON ApiInfo where
  parseJSON = withObject "ApiInfo" $ \o ->
    ApiInfo
      <$> o .: "scan_credits"
      <*> o .: "usage_limits"
      <*> o .: "plan"
      <*> o .: "https"
      <*> o .: "unlocked"
      <*> o .: "query_credits"
      <*> o .: "monitored_ips"
      <*> o .: "unlocked_left"
      <*> o .: "telnet"

instance FromJSON UsageLimits where
  parseJSON = withObject "UsageLimits" $ \o ->
    UsageLimits
      <$> o .: "scan_credits"
      <*> o .: "query_credits"
      <*> o .: "monitored_ips"
