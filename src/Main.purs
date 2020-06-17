-- | Module: Main
-- | Description: Main entrypoint for the Cantilever executable application.
-- |
-- | Reads process command-line arguments, parses subcommands, and executes CLI actions.

module Main
  ( main
  ) where

import Prelude

import Cantilever.CLI.Args (parseCLIArgs)
import Cantilever.CLI.Commands (executeCommand)
import Effect (Effect)

-- | Foreign JS binding to retrieve command line arguments (skipping node and script).
foreign import getProcessArgv :: Effect (Array String)

-- | Application entrypoint.
main :: Effect Unit
main = do
  argv <- getProcessArgv
  let cmd = parseCLIArgs argv
  executeCommand cmd
