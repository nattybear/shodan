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
  let match = SearchMatch "96.93.212.27" 443 (Just "nginx") Nothing (Just "AS7922")
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
    Right (SearchMatch "192.0.2.1" 443 (Just "nginx") (Just "1.26.2") Nothing))
  let minimal = SearchMatch "2001:db8::1" 0 Nothing Nothing Nothing
  check "IPv6 and absent optional fields" (eitherDecode'
    "{\"ip_str\":\"2001:db8::1\",\"port\":0}" == Right minimal)
  check "null optional fields and maximum port" (eitherDecode'
    "{\"ip_str\":\"192.0.2.1\",\"port\":65535,\"product\":null,\"version\":null,\"asn\":null}" ==
    Right (SearchMatch "192.0.2.1" 65535 Nothing Nothing Nothing))
  let twoMatches = "{\"total\":2,\"matches\":[{\"ip_str\":\"192.0.2.1\",\"port\":80},{\"ip_str\":\"192.0.2.1\",\"port\":443}],\"facets\":{}}"
  check "multiple services on one IP retain order" (eitherDecode' twoMatches ==
    Right (SearchResult 2
      [SearchMatch "192.0.2.1" 80 Nothing Nothing Nothing,
       SearchMatch "192.0.2.1" 443 Nothing Nothing Nothing] Map.empty))
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
