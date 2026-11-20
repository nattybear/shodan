module Main (main) where

import           Data.Char          (isSpace)
import qualified Data.Text          as Text
import           Shodan             (ApiInfo (..), ShodanError (..), getApiInfo,
                                     newClient)
import           System.Environment (lookupEnv)
import           System.Exit        (die)

main :: IO ()
main = do
  configuredKey <- lookupEnv "SHODAN_API_KEY"
  case configuredKey of
    Nothing -> die "Set the SHODAN_API_KEY environment variable before running."
    Just key
      | all isSpace key -> die "SHODAN_API_KEY must not be empty or whitespace."
      | otherwise -> do
          client <- newClient (Text.pack key)
          result <- getApiInfo client
          case result of
            Left err -> die (errorMessage err)
            Right info -> do
              putStrLn ("Plan: " ++ Text.unpack (apiInfoPlan info))
              putStrLn ("Query credits: " ++ show (apiInfoQueryCredits info))
              putStrLn ("Scan credits: " ++ show (apiInfoScanCredits info))

errorMessage :: ShodanError -> String
errorMessage NetworkError = "Could not reach Shodan (connection failure or timeout)."
errorMessage (HttpError status) = "Shodan returned HTTP " ++ show status ++ "."
errorMessage InvalidResponse = "Shodan returned an unexpected response."
errorMessage InvalidPage = "Page numbers must be at least 1."
errorMessage InvalidDomain = "Expected an ASCII DNS domain name without a URL or trailing dot."
