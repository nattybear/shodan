{-# LANGUAGE OverloadedStrings #-}

module DnsTests (dnsParsingTests) where

import           Control.Monad     (unless)
import           Data.Aeson        (Value (..), eitherDecode', encode, object,
                                    toJSON, (.=))
import qualified Data.Aeson.KeyMap as KeyMap
import           Shodan

-- Same response shape as the official /dns/domain example, with reserved names.
dnsParsingTests :: IO ()
dnsParsingTests = do
  let record = DnsRecord "www" "A" "192.0.2.1" "2026-11-21T01:02:03+00:00"
      wanted = DomainInfo "example.com" ["ipv6"] [record] ["www", "*.api"] True
      recordJSON = object ["subdomain" .= String "www", "type" .= String "A",
        "value" .= String "192.0.2.1", "last_seen" .= String "2026-11-21T01:02:03+00:00"]
      response = object ["domain" .= String "example.com", "tags" .= [String "ipv6"],
        "data" .= [recordJSON], "subdomains" .= [String "www", String "*.api"],
        "more" .= True, "future" .= Null]
      decode value = eitherDecode' (encode value) :: Either String DomainInfo
      check label ok = unless ok (fail label)
      reject value = check "invalid domain response accepted" (case decode value of
        Left _  -> True
        Right _ -> False)
      modifyRecord change = case response of
        Object o -> Object (KeyMap.insert "data" (toList (change recordJSON)) o)
        _        -> response
      toList value = toJSON [value]
      alter f (Object o) = Object (f o)
      alter _ value      = value
  check "domain response fields" (decode response == Right wanted)
  check "empty DNS lists" (eitherDecode'
    "{\"domain\":\"example.com\",\"tags\":[],\"data\":[],\"subdomains\":[],\"more\":false}" ==
    Right (DomainInfo "example.com" [] [] [] False))
  check "apex, unknown type, and timezone text preserved" (eitherDecode'
    "{\"subdomain\":\"\",\"type\":\"FUTURE\",\"value\":\"opaque value\",\"last_seen\":\"observed\",\"extra\":true}" ==
    Right (DnsRecord "" "FUTURE" "opaque value" "observed"))
  check "CNAME and wildcard preserved" (eitherDecode'
    "{\"subdomain\":\"*.api\",\"type\":\"CNAME\",\"value\":\"www.example.net\",\"last_seen\":\"2026-11-21T01:02:03Z\"}" ==
    Right (DnsRecord "*.api" "CNAME" "www.example.net" "2026-11-21T01:02:03Z"))
  mapM_ (\field -> do
    reject (alter (KeyMap.delete field) response)
    reject (alter (KeyMap.insert field Null) response))
    ["domain", "tags", "data", "subdomains", "more"]
  mapM_ (\field -> do
    reject (modifyRecord (alter (KeyMap.delete field)))
    reject (modifyRecord (alter (KeyMap.insert field Null)))
    reject (modifyRecord (alter (KeyMap.insert field (Number 42)))))
    ["subdomain", "type", "value", "last_seen"]
  mapM_ (\(field, value) -> reject (alter (KeyMap.insert field value) response))
    [("domain", Bool True), ("tags", String "ipv6"), ("data", object []),
     ("subdomains", toList (Number 42)), ("more", String "true")]
  reject (modifyRecord (const (String "not an object")))
