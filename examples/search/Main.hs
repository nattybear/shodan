module Main (main) where

import           Data.Char          (isSpace)
import           Data.List          (intercalate)
import qualified Data.Text          as Text
import           Shodan             (SearchMatch (..), SearchResult (..),
                                     newClient, searchHosts)
import           System.Environment (getArgs, lookupEnv)
import           System.Exit        (die)
import           Text.Read          (readMaybe)

main :: IO ()
main = do
  arguments <- getArgs
  (query, page) <- parseArguments arguments
  configuredKey <- lookupEnv "SHODAN_API_KEY"
  case configuredKey of
    Nothing -> die "Set the SHODAN_API_KEY environment variable before running."
    Just key
      | all isSpace key -> die "SHODAN_API_KEY must not be empty or whitespace."
      | otherwise -> do
          client <- newClient (Text.pack key)
          result <- searchHosts client query page
          case result of
            Left err -> die ("Shodan search failed: " ++ show err)
            Right found -> do
              putStrLn ("Total: " ++ show (searchTotal found))
              putStrLn ("Page: " ++ show page)
              putStrLn ("Returned: " ++ show (length (searchMatches found)))
              putStrLn "IP\tPORT\tPRODUCT\tVERSION\tASN"
              mapM_ printMatch (searchMatches found)

parseArguments :: [String] -> IO (Text.Text, Int)
parseArguments [query] = parseArguments [query, "1"]
parseArguments [query, pageText]
  | not (all isSpace query)
  , Just page <- (readMaybe pageText :: Maybe Integer)
  , page >= 1
  , page <= toInteger (maxBound :: Int) = pure (Text.pack query, fromInteger page)
parseArguments _ = die "Usage: shodan-search 'QUERY' [PAGE >= 1]"

printMatch :: SearchMatch -> IO ()
printMatch match = putStrLn (intercalate "\t"
  [ Text.unpack (matchIp match)
  , show (matchPort match)
  , maybe "-" Text.unpack (matchProduct match)
  , maybe "-" Text.unpack (matchVersion match)
  , maybe "-" Text.unpack (matchAsn match)
  ])
