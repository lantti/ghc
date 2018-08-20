module Main where
    
import System.Process
import System.Environment
import System.FilePath
import Control.Monad

dimensions = [3,2,1] 

explode :: [String] -> IO ()
explode [] = explode (map show dimensions)
explode ("leaf":[]) = forever (return ())
explode (x:[]) = explode' (read x) "./forkbombnowait" ["leaf"]
explode (x:xs) = explode' (read x) "./forkbombnowait" xs

explode' n c a = do cproc <- return (proc c a) {std_in = NoStream,
                                                std_out = NoStream,
                                                std_err = NoStream}
                    replicateM_ n (createProcess cproc) 

main = getArgs >>= explode
