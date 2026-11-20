{-# LANGUAGE OverloadedStrings #-}

module SearchTests (searchParsingTests) where

import           Control.Monad        (unless)
import           Data.Aeson           (Value (..), eitherDecode')
import qualified Data.ByteString.Lazy as Lazy
import qualified Data.Map.Strict      as Map
import           Shodan

searchParsingTests :: IO ()
searchParsingTests = do
  -- Selected fields from the official GET /shodan/host/search example.
  -- Source: https://developer.shodan.io/api
  let match = SearchMatch "96.93.212.27" 443 (Just "nginx") Nothing (Just "AS7922") Nothing Nothing Nothing Nothing Nothing
      expected = SearchResult 23047224 [match]
        (Map.singleton "country" [Facet (String "US") 7883733])
      example = "{\"total\":23047224,\"matches\":[{\"ip_str\":\"96.93.212.27\",\"port\":443,\"product\":\"nginx\",\"asn\":\"AS7922\",\"http\":{\"server\":\"nginx\"}}],\"facets\":{\"country\":[{\"value\":\"US\",\"count\":7883733}]}}"
  check "documented search fields" (eitherDecode' example == Right expected)
  check "empty search" (eitherDecode' "{\"total\":0,\"matches\":[]}" ==
    Right (SearchResult 0 [] Map.empty))
  check "total can exceed page size" (eitherDecode'
    "{\"total\":100000000000000000000,\"matches\":[],\"future\":true}" ==
    Right (SearchResult 100000000000000000000 [] Map.empty))
  check "product version" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"product\":\"nginx\",\"version\":\"1.26.2\"}" ==
    Right (SearchMatch "192.0.2.1" 443 (Just "nginx") (Just "1.26.2") Nothing Nothing Nothing Nothing Nothing Nothing))
  check "complete metadata" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"timestamp\":\"2026-11-21T01:02:03.123456\",\"hostnames\":[\"www.example.com\",\"api.example.com\"],\"domains\":[\"example.com\"],\"ssl\":{\"alpn\":[\"h2\",\"http/1.1\"],\"future\":true}}" ==
    Right (SearchMatch "192.0.2.1" 443 Nothing Nothing Nothing (Just "2026-11-21T01:02:03.123456") (Just ["www.example.com", "api.example.com"]) (Just ["example.com"]) (Just ["h2", "http/1.1"]) Nothing))
  check "empty metadata lists" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"hostnames\":[],\"domains\":[],\"ssl\":{\"alpn\":[]}}" ==
    Right (SearchMatch "192.0.2.1" 443 Nothing Nothing Nothing Nothing (Just []) (Just []) (Just []) Nothing))
  check "null metadata" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"timestamp\":null,\"hostnames\":null,\"domains\":null,\"ssl\":null}" ==
    Right (SearchMatch "192.0.2.1" 443 Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing))
  check "missing ALPN in ssl" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{}}" ==
    Right (SearchMatch "192.0.2.1" 443 Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing))
  check "null ALPN" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"alpn\":null}}" ==
    Right (SearchMatch "192.0.2.1" 443 Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing))
  check "SAN DNS names and wildcard" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[{\"name\":\"subjectAltName\",\"data\":\"0&\\\\x82\\\\x0fwww.example.com\\\\x82\\\\x0d*.example.com\\\\x87\\\\x04abcd\"}]}}}" ==
    Right (SearchMatch "192.0.2.1" 443 Nothing Nothing Nothing Nothing Nothing Nothing Nothing (Just ["www.example.com", "*.example.com"])))
  check "raw DER SAN" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[{\"name\":\"subjectAltName\",\"data\":\"0&\\u0082\\u000fwww.example.com\\u0082\\r*.example.com\\u0087\\u0004abcd\"}]}}}" ==
    Right (SearchMatch "192.0.2.1" 443 Nothing Nothing Nothing Nothing Nothing Nothing Nothing (Just ["www.example.com", "*.example.com"])))
  check "empty SAN" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[{\"name\":\"subjectAltName\",\"data\":\"0\\\\x00\"}]}}}" ==
    Right (SearchMatch "192.0.2.1" 443 Nothing Nothing Nothing Nothing Nothing Nothing Nothing (Just [])))
  check "IP-only SAN" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[{\"name\":\"subjectAltName\",\"data\":\"0\\\\x06\\\\x87\\\\x04abcd\"}]}}}" ==
    Right (SearchMatch "192.0.2.1" 443 Nothing Nothing Nothing Nothing Nothing Nothing Nothing (Just [])))
  check "absent SAN" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[{\"name\":\"keyUsage\"}]}}}" ==
    Right (SearchMatch "192.0.2.1" 443 Nothing Nothing Nothing Nothing Nothing Nothing Nothing (Nothing)))
  check "absent extensions" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{}}}" ==
    Right (SearchMatch "192.0.2.1" 443 Nothing Nothing Nothing Nothing Nothing Nothing Nothing (Nothing)))
  check "null certificate" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":null}}" ==
    Right (SearchMatch "192.0.2.1" 443 Nothing Nothing Nothing Nothing Nothing Nothing Nothing (Nothing)))
  check "null extensions" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":null}}}" ==
    Right (SearchMatch "192.0.2.1" 443 Nothing Nothing Nothing Nothing Nothing Nothing Nothing (Nothing)))
  check "long DER length" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[{\"name\":\"subjectAltName\",\"data\":\"0\\\\x81\\\\x96\\\\x82\\\\x0da.example.com\\\\x82\\\\x0da.example.com\\\\x82\\\\x0da.example.com\\\\x82\\\\x0da.example.com\\\\x82\\\\x0da.example.com\\\\x82\\\\x0da.example.com\\\\x82\\\\x0da.example.com\\\\x82\\\\x0da.example.com\\\\x82\\\\x0da.example.com\\\\x82\\\\x0da.example.com\"}]}}}" ==
    Right (SearchMatch "192.0.2.1" 443 Nothing Nothing Nothing Nothing Nothing Nothing Nothing (Just (replicate 10 "a.example.com"))))
  let minimal = SearchMatch "2001:db8::1" 0 Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing
  check "IPv6 and absent optional fields" (eitherDecode'
    "{\"ip_str\":\"2001:db8::1\",\"port\":0}" == Right minimal)
  check "null optional fields and maximum port" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":65535,\"product\":null,\"version\":null,\"asn\":null}" ==
    Right (SearchMatch "192.0.2.1" 65535 Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing))
  let twoMatches = "{\"total\":2,\"matches\":[{\"ip_str\":\"192.0.2.1\",\"port\":80},{\"ip_str\":\"192.0.2.1\",\"port\":443}],\"facets\":{}}"
  check "multiple services on one IP retain order" (eitherDecode' twoMatches ==
    Right (SearchResult 2
      [SearchMatch "192.0.2.1" 80 Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing,
       SearchMatch "192.0.2.1" 443 Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing] Map.empty))
  mapM_ rejectsMatch
    [ ("missing IP", "{\"port\":443}")
    , ("null IP", "{\"ip_str\":null,\"port\":443}")
    , ("numeric IP", "{\"ip_str\":123,\"port\":443}")
    , ("missing port", "{\"ip_str\":\"192.0.2.1\"}")
    , ("null port", "{\"ip_str\":\"192.0.2.1\",\"port\":null}")
    , ("fractional port", "{\"ip_str\":\"192.0.2.1\",\"port\":1.5}")
    , ("negative port", "{\"ip_str\":\"192.0.2.1\",\"port\":-1}")
    , ("out-of-range port", "{\"ip_str\":\"192.0.2.1\",\"port\":65536}")
    , ("wrong product type", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"product\":true}")
    , ("numeric version", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"version\":126}")
    , ("object version", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"version\":{}}")
    , ("wrong ASN type", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"asn\":65536}")
    , ("numeric timestamp", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"timestamp\":42}")
    , ("object timestamp", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"timestamp\":{}}")
    , ("string hostnames", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"hostnames\":\"example.com\"}")
    , ("non-text hostname", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"hostnames\":[null]}")
    , ("object domains", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"domains\":{}}")
    , ("non-text domain", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"domains\":[42]}")
    , ("non-object ssl", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":[]}")
    , ("string ssl", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":\"TLS\"}")
    , ("string ALPN", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"alpn\":\"h2\"}}")
    , ("non-text ALPN", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"alpn\":[\"h2\",3]}}")
    , ("non-object certificate", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":[]}}")
    , ("non-list extensions", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":{}}}}")
    , ("non-object extension", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[3]}}}")
    , ("missing extension name", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[{}]}}}")
    , ("missing SAN data", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[{\"name\":\"subjectAltName\"}]}}}")
    , ("non-text SAN data", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[{\"name\":\"subjectAltName\",\"data\":42}]}}}")
    , ("truncated SAN", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[{\"name\":\"subjectAltName\",\"data\":\"0\\\\x05\\\\x82\\\\x03ab\"}]}}}")
    , ("trailing SAN bytes", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[{\"name\":\"subjectAltName\",\"data\":\"0\\\\x00x\"}]}}}")
    , ("invalid SAN escape", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[{\"name\":\"subjectAltName\",\"data\":\"\\\\xZZ\"}]}}}")
    , ("indefinite length", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[{\"name\":\"subjectAltName\",\"data\":\"0\\\\x80\"}]}}}")
    , ("nonminimal DER length", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[{\"name\":\"subjectAltName\",\"data\":\"0\\\\x81\\\\x00\"}]}}}")
    , ("empty DNS name", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[{\"name\":\"subjectAltName\",\"data\":\"0\\\\x02\\\\x82\\\\x00\"}]}}}")
    , ("non-ASCII DNS name", "{\"ip_str\":\"192.0.2.1\",\"port\":443,\"ssl\":{\"cert\":{\"extensions\":[{\"name\":\"subjectAltName\",\"data\":\"0\\\\x03\\\\x82\\\\x01\\\\xff\"}]}}}")
    , ("non-object match", "[]")
    ]
  mapM_ rejectsSearch
    [ ("missing total", "{\"matches\":[]}")
    , ("negative total", "{\"total\":-1,\"matches\":[]}")
    , ("fractional total", "{\"total\":1.5,\"matches\":[]}")
    , ("missing matches", "{\"total\":0}")
    , ("null matches", "{\"total\":0,\"matches\":null}")
    , ("object matches", "{\"total\":0,\"matches\":{}}")
    , ("invalid nested match", "{\"total\":1,\"matches\":[{}]}")
    , ("null facets", "{\"total\":0,\"matches\":[],\"facets\":null}")
    , ("invalid nested facet", "{\"total\":0,\"matches\":[],\"facets\":{\"country\":[{}]}}")
    , ("non-object search", "[]")
    , ("malformed JSON", "not JSON")
    ]

check :: String -> Bool -> IO ()
check label success = unless success (fail label)

rejectsMatch :: (String, Lazy.ByteString) -> IO ()
rejectsMatch (label, body) = case eitherDecode' body :: Either String SearchMatch of
  Left _  -> pure ()
  Right _ -> fail (label ++ ": unexpectedly accepted")

rejectsSearch :: (String, Lazy.ByteString) -> IO ()
rejectsSearch (label, body) = case eitherDecode' body :: Either String SearchResult of
  Left _  -> pure ()
  Right _ -> fail (label ++ ": unexpectedly accepted")
