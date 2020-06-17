#!/usr/bin/env node

// Cantilever CLI executable runner
import { main } from "../output/Main/index.js";

try {
  main();
} catch (err) {
  console.error("[FATAL] Cantilever process encountered an unhandled exception:", err);
  process.exit(1);
}
