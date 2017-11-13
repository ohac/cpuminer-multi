#!/bin/bash
set -e
emcc yescrypt.c yescrypt-opt.c sha2.c sha256_Y.c util.c cpu-miner.c -O3 -s WASM=1 \
  -s EXPORTED_FUNCTIONS="['_sha256d_str', '_miner_thread']" \
  -o wasmminer.html
