module Main (main) where

import           Data.Char          (isSpace)
import           Data.List          (intercalate)
import qualified Data.Text          as Text
import           Shodan             (DnsRecord (..), DomainInfo (..),
                                     getDomainInfo, newClient)
import           System.Environment (getArgs, lookupEnv)
import           System.Exit        (die)
import           Text.Read          (readMaybe)

main :: IO ()
main = do
  arguments <- getArgs
  (domain, page) <- parseArguments arguments
  configuredKey <- lookupEnv "SHODAN_API_KEY"
  case configuredKey of
    Nothing -> die "Set the SHODAN_API_KEY environment variable before running."
    Just key
      | all isSpace key -> die "SHODAN_API_KEY must not be empty or whitespace."
      | otherwise -> do
          client <- newClient (Text.pack key)
          result <- getDomainInfo client domain page
          case result of
            Left err -> die ("Shodan domain lookup failed: " ++ show err)
            Right found -> do
              putStrLn ("Domain: " ++ Text.unpack (domainName found))
              putStrLn ("Page: " ++ show page)
              putStrLn ("More: " ++ show (domainMore found))
              putStrLn ("Subdomains: " ++ renderNames (domainSubdomains found))
              putStrLn "HOSTNAME\tTYPE\tVALUE\tLAST_SEEN"
              mapM_ (printRecord (domainName found)) (domainRecords found)

parseArguments :: [String] -> IO (Text.Text, Int)
parseArguments [domain] = parseArguments [domain, "1"]
parseArguments [domain, pageText]
  | not (all isSpace domain)
  , Just page <- (readMaybe pageText :: Maybe Integer)
  , page >= 1
  , page <= toInteger (maxBound :: Int) = pure (Text.pack domain, fromInteger page)
parseArguments _ = die "Usage: shodan-domain DOMAIN [PAGE >= 1]"

-- Empty relative names refer to the apex. Wildcards remain literal.
printRecord :: Text.Text -> DnsRecord -> IO ()
printRecord domain record = putStrLn (intercalate "\t"
  [ Text.unpack (if Text.null (dnsSubdomain record) then domain
      else dnsSubdomain record <> Text.pack "." <> domain)
  , Text.unpack (dnsType record)
  , Text.unpack (dnsValue record)
  , Text.unpack (dnsLastSeen record)
  ])

renderNames :: [Text.Text] -> String
renderNames []     = "[]"
renderNames values = intercalate "," (map Text.unpack values)
