module Main (main) where

import           Data.Char          (isSpace)
import qualified Data.Text          as Text
import           Shodan             (CountResult (..), countHosts, newClient)
import           System.Environment (getArgs, lookupEnv)
import           System.Exit        (die)

main :: IO ()
main = do
  arguments <- getArgs
  query <- case arguments of
    [value] | not (all isSpace value) -> pure (Text.pack value)
    _                                 -> die "Usage: shodan-count 'QUERY'"
  configuredKey <- lookupEnv "SHODAN_API_KEY"
  case configuredKey of
    Nothing -> die "Set the SHODAN_API_KEY environment variable before running."
    Just key
      | all isSpace key -> die "SHODAN_API_KEY must not be empty or whitespace."
      | otherwise -> do
          client <- newClient (Text.pack key)
          result <- countHosts client query
          case result of
            Left err    -> die ("Shodan count failed: " ++ show err)
            Right count -> print (countTotal count)
