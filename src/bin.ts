#!/usr/bin/env node
import { runSignerCli } from './cli'

runSignerCli(process.argv.slice(2), process.env, process).then((exitCode) => {
  process.exitCode = exitCode
})
