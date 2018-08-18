module Main where
    
import System.Process
import System.Environment
import System.FilePath
import Control.Monad

dimensions = [3,2,1] 

explode :: [String] -> IO ()
explode [] = explode (map show dimensions)
explode ("leaf":[]) = forever (return ())
explode (x:[]) = explode' (read x) "./forkbomb" ["leaf"]
explode (x:xs) = explode' (read x) "./forkbomb" xs

explode' n c a = replicateM n (spawnProcess c a) >>= (mapM_ waitForProcess)

main = getArgs >>= explode
