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
  , getDomainInfo
  , DomainInfo (..)
  , DnsRecord (..)
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
import           Data.Aeson.Types        (Parser)
import           Data.Char               (chr, digitToInt, isHexDigit, ord)
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
    -- ^ Search and DNS page numbers must be at least 1. No request was made.
  | InvalidDomain
    -- ^ Expected an ASCII DNS name (use punycode for international names),
    -- without a URL, trailing dot, empty label, or leading/trailing hyphen.
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

-- | Retrieve one page of @GET /dns/domain/{domain}@. Shodan documents 100
-- records per page, but observed responses can exceed this; use 'domainMore'
-- rather than the record count to determine whether another page is available.
-- Uses one query credit per lookup according to the official API documentation.
-- Page numbers start at 1; additional pages are never fetched automatically.
-- Use 'domainMore' to decide whether to request the next page. The API defaults
-- are used: no historical records and no record-type filter.
-- Domain names must consist of ASCII labels of 1-63 letters, digits or hyphens,
-- with a total length of at most 253, and no leading/trailing label hyphens.
-- International names must be supplied in punycode; no DNS resolution is done.
-- Invalid pages or names are rejected before HTTP. Returned DNS data is an
-- observation by Shodan, not a guarantee of a current mapping or a complete list.
getDomainInfo :: Client -> Text -> Int -> IO (Either ShodanError DomainInfo)
getDomainInfo client domain page
  | page < 1 = pure (Left InvalidPage)
  | not (validDomain domain) = pure (Left InvalidDomain)
  | otherwise = getJSON client ("/dns/domain/" <> domain)
      [("page", DataText.pack (show page))]

validDomain :: Text -> Bool
validDomain domain = DataText.length domain <= 253 &&
  all validLabel (DataText.splitOn "." domain)
  where
    validLabel label = not (DataText.null label) && DataText.length label <= 63 &&
      not (DataText.isPrefixOf "-" label || DataText.isSuffixOf "-" label) &&
      DataText.all (\c -> asciiLetter c || (c >= '0' && c <= '9') || c == '-') label
    asciiLetter c = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')

-- | One observed DNS record. All fields are required strings; unknown JSON
-- fields are ignored. Empty subdomains denote the apex domain. Wildcard names
-- are preserved. Type and value remain text for forward compatibility; neither
-- DNS syntax nor the timestamp format is validated during response parsing.
data DnsRecord = DnsRecord
  { dnsSubdomain :: Text
    -- ^ Relative name, for example @www@, @*.api@, or empty for the apex.
  , dnsType      :: Text
    -- ^ Record type such as @A@, @AAAA@, @CNAME@, @MX@, or @TXT@.
  , dnsValue     :: Text
    -- ^ Record value, preserved as returned rather than interpreted as an IP.
  , dnsLastSeen  :: Text
    -- ^ Shodan's last-observed timestamp, including its supplied timezone.
  } deriving (Eq, Show)

instance FromJSON DnsRecord where
  parseJSON = withObject "DnsRecord" $ \o -> DnsRecord
    <$> o .: "subdomain"
    <*> o .: "type"
    <*> o .: "value"
    <*> o .: "last_seen"

-- | A single page of domain information. All fields are required and unknown
-- fields are ignored. Lists preserve order, including wildcards and duplicates.
-- Empty lists are valid; missing/null lists and malformed records are rejected.
data DomainInfo = DomainInfo
  { domainName       :: Text
    -- ^ Domain as reported by Shodan.
  , domainTags       :: [Text]
    -- ^ Tags associated with this domain.
  , domainRecords    :: [DnsRecord]
    -- ^ DNS records on this page; not automatically combined with later pages.
  , domainSubdomains :: [Text]
    -- ^ Relative subdomain names returned by the API, not recomputed from records.
  , domainMore       :: Bool
    -- ^ Whether more DNS record pages are available.
  } deriving (Eq, Show)

instance FromJSON DomainInfo where
  parseJSON = withObject "DomainInfo" $ \o -> DomainInfo
    <$> o .: "domain"
    <*> o .: "tags"
    <*> o .: "data"
    <*> o .: "subdomains"
    <*> o .: "more"

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
  { matchIp               :: Text
    -- ^ Required @ip_str@ field, usable for IPv4 or IPv6 text.
  , matchPort             :: Int
    -- ^ Required integer port, from 0 through 65535.
  , matchProduct          :: Maybe Text
    -- ^ Detected product; absent or null means 'Nothing'.
  , matchVersion          :: Maybe Text
    -- ^ Detected product version; absent or null means 'Nothing'.
  , matchAsn              :: Maybe Text
    -- ^ ASN such as @AS65536@; absent or null means 'Nothing'.
  , matchTimestamp        :: Maybe Text
    -- ^ Banner collection time in UTC, preserved as supplied; not date-validated.
  , matchHostnames        :: Maybe [Text]
    -- ^ Hostnames based on reverse DNS; not an exhaustive list of hosted sites.
  , matchDomains          :: Maybe [Text]
    -- ^ Domains reported by Shodan, preserving order.
  , matchAlpn             :: Maybe [Text]
    -- ^ Observed @ssl.alpn@ protocols, such as @h2@ and @http/1.1@.
    -- Missing data does not imply that a protocol is unsupported.
  , matchCertificateNames :: Maybe [Text]
    -- ^ DNS names from the leaf certificate's @subjectAltName@ extension.
    -- Wildcards and order are preserved; IP, URI and email entries are omitted.
    -- These names are candidates, not verified DNS mappings or live sites.
    -- Missing certificate/extensions/SAN means 'Nothing'; a SAN without DNS
    -- entries yields @Just []@. Malformed SAN data rejects the response.
  } deriving (Eq, Show)

instance FromJSON SearchMatch where
  parseJSON = withObject "SearchMatch" $ \o -> do
    ip <- o .: "ip_str"
    port <- o .: "port"
    productName <- o .:? "product"
    version <- o .:? "version"
    asn <- o .:? "asn"
    timestamp <- o .:? "timestamp"
    hostnames <- o .:? "hostnames"
    domains <- o .:? "domains"
    ssl <- o .:? "ssl"
    (alpn, certificateNames) <- case ssl of
      Nothing -> pure (Nothing, Nothing)
      Just value -> withObject "ssl" (\tls -> do
        protocols <- tls .:? "alpn"
        cert <- tls .:? "cert"
        names <- case cert of
          Nothing -> pure Nothing
          Just certificate -> withObject "certificate" (\c -> do
            extensions <- c .:? "extensions"
            case extensions of
              Nothing -> pure Nothing
              Just entries -> do
                decoded <- mapM parseCertificateExtension entries
                let sans = [names | Just names <- decoded]
                pure (if null sans then Nothing else Just (concat sans))) certificate
        pure (protocols, names)) value
    if port < 0 || port > 65535
      then fail "Search match port must be between 0 and 65535"
      else pure (SearchMatch ip port productName version asn timestamp hostnames domains alpn certificateNames)

-- Shodan represents extension DER as text, sometimes with literal Python-style
-- escapes (as in its official example). Decode bytes before reading the SAN.
parseCertificateExtension :: Value -> Parser (Maybe [Text])
parseCertificateExtension value = withObject "certificate extension" (\extension -> do
  name <- extension .: "name"
  if name /= ("subjectAltName" :: Text)
    then pure Nothing
    else do
      raw <- extension .: "data"
      case decodeSan raw of
        Left message -> fail message
        Right names  -> pure (Just names)) value

decodeSan :: Text -> Either String [Text]
decodeSan raw = do
  bytes <- unescape (DataText.unpack raw)
  (tag, body, rest) <- tlv bytes
  if tag /= 48 || not (null rest)
    then Left "SAN must be a DER sequence"
    else names body
  where
    unescape [] = Right []
    unescape ('\\':'x':a:b:xs)
      | isHexDigit a && isHexDigit b =
          ((16 * digitToInt a + digitToInt b) :) <$> unescape xs
    unescape ('\\':c:xs) = case lookup c
        [('n',10), ('r',13), ('t',9), ('\\',92), ('\'',39), ('"',34)] of
      Just byte -> (byte :) <$> unescape xs
      Nothing   -> Left "Invalid escaped SAN byte"
    unescape (c:xs)
      | ord c <= 255 = (ord c :) <$> unescape xs
      | otherwise = Left "SAN contains a non-byte character"
    names [] = Right []
    names bytes = do
      (tag, body, rest) <- tlv bytes
      following <- names rest
      if tag == 130
        then if null body || any (> 127) body
          then Left "Invalid SAN DNS name"
          else pure (DataText.pack (map chr body) : following)
        else pure following

-- Only definite, minimally encoded DER lengths are accepted. Bound the length
-- octets before converting to Int, and check available input before splitting.
tlv :: [Int] -> Either String (Int, [Int], [Int])
tlv (tag:first:rest)
  | tag `mod` 32 == 31 = Left "Unsupported SAN tag"
  | first < 128 = takeBody first rest
  | otherwise =
      let count = first - 128
          (digits, remaining) = splitAt count rest
          size = foldl (\n byte -> n * 256 + toInteger byte) 0 digits
      in if count < 1 || count > 4 || length digits /= count ||
            take 1 digits == [0] || size < 128 || size > toInteger (length remaining)
        then Left "Invalid SAN DER length"
        else takeBody (fromInteger size) remaining
  where
    takeBody size bytes
      | size > length bytes = Left "Truncated SAN DER value"
      | otherwise = let (body, remaining) = splitAt size bytes
                    in Right (tag, body, remaining)
tlv _ = Left "Truncated SAN DER header"

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
