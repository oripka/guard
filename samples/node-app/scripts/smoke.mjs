import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'

mkdirSync('.guard-smoke', { recursive: true })
writeFileSync('.guard-smoke/out.txt', 'ok\n')
readFileSync('package.json', 'utf8')
console.log('sample smoke ok')
