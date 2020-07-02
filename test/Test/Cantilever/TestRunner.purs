-- | Module: Test.Cantilever.TestRunner
-- | Description: Test assertion helpers and summary reporter.

module Test.Cantilever.TestRunner
  ( assert
  , assertEq
  , runTestSuite
  ) where

import Prelude

import Effect (Effect)
import Effect.Console (log)
import Effect.Exception (throwException, error)

-- | Asserts a boolean condition, logging success or throwing on failure.
assert :: String -> Boolean -> Effect Unit
assert desc condition =
  if condition then
    log $ "    ✓ " <> desc
  else do
    log $ "    ✗ FAILED: " <> desc
    throwException (error $ "Assertion failed: " <> desc)

-- | Asserts equality between two values with detailed error message on mismatch.
assertEq :: forall a. Eq a => Show a => String -> a -> a -> Effect Unit
assertEq desc expected actual =
  if expected == actual then
    log $ "    ✓ " <> desc
  else do
    log $ "    ✗ FAILED: " <> desc <> "\n      Expected: " <> show expected <> "\n      Actual:   " <> show actual
    throwException (error $ "Assertion failed for " <> desc)

-- | Runs a named test suite block with header and footer.
runTestSuite :: String -> Effect Unit -> Effect Unit
runTestSuite name suiteAction = do
  log $ "\n[TEST SUITE] " <> name
  suiteAction
  log $ "[PASSED] " <> name
