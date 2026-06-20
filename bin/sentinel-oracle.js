#!/usr/bin/env node
'use strict'
const path = require('path')
const fs = require('fs')

const args = process.argv.slice(2)
const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'))

if (args.includes('--version') || args.includes('-v')) {
  console.log(pkg.version)
  process.exit(0)
}

if (args.includes('--help') || args.includes('-h') || args.includes('help')) {
  console.log(`
sentinel-oracle v${pkg.version}

Usage:
  sentinel-oracle                    Start the server (default)
  sentinel-oracle start              Start the server
  sentinel-oracle scan               Run a one-time security scan on the configured repository
  sentinel-oracle --version, -v      Print version
  sentinel-oracle --help, -h         Print this help

Environment:
  SENTINEL_CONFIG_DIR    Configuration directory (default: ~/.config/sentinel-oracle)
  SENTINEL_PORT          HTTPS server port (default: 8443)
  SENTINEL_HOST          Bind address (default: localhost)
  NODE_OPTIONS           Passed to Node.js (e.g. --max-old-space-size=4096)

The server starts in setup mode if GitHub credentials are not configured.
Configure via the web UI at https://localhost:{PORT}/setup after starting.

Documentation: https://github.com/javier20dev25/sentinel-oracle
`)
  process.exit(0)
}

if (args[0] === 'scan') {
  const { runScan } = require(path.join(__dirname, '..', 'dist', 'scan'))
  runScan().catch(err => {
    console.error('Scan failed:', err.message)
    process.exit(1)
  })
  return
}

// Default: start the server
require(path.join(__dirname, '..', 'dist', 'index.js'))
