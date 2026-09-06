// A stand-in for the hsd SPV launcher (src/hns/hsd-spv-launcher.cjs), spawned
// by tests/hns/spv-cold-start.test.js exactly the way src/hns/spv.js spawns
// the real one: with the runtime, the same argv, and HSD_API_KEY in the env.
//
//   FAKE_HSD_MODE=fail   print what hsd prints on a held port, exit 1
//   (default)            answer getblockchaininfo on --http-port until killed
//
// It writes its argv to FAKE_HSD_ARGS_FILE when that is set, so a test can
// assert on what the supervisor passed.

const fs = require('node:fs')
const http = require('node:http')

const args = process.argv.slice(2)
const arg = (name) => {
  const hit = args.find((a) => a.startsWith(`--${name}=`))
  return hit ? hit.slice(name.length + 3) : null
}
if (process.env.FAKE_HSD_ARGS_FILE) fs.writeFileSync(process.env.FAKE_HSD_ARGS_FILE, JSON.stringify(args))

const port = Number(arg('http-port'))
if (process.env.FAKE_HSD_MODE === 'fail') {
  process.stderr.write(`Error: listen EADDRINUSE: address already in use 127.0.0.1:${port}\n` +
    '    at Server.setupListenHandle [as _listen2] (node:net:1940:16)\n' +
    '    at listenInCluster (node:net:1997:12)\n')
  process.exit(1)
}

const key = process.env.HSD_API_KEY || ''
const server = http.createServer((req, res) => {
  const auth = req.headers.authorization || ''
  const expected = 'Basic ' + Buffer.from(`x:${key}`).toString('base64')
  if (key && auth !== expected) {
    res.statusCode = 401
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ result: null, error: { message: 'Unauthorized' } }))
    return
  }
  let body = ''
  req.on('data', (c) => { body += c })
  req.on('end', () => {
    res.setHeader('Content-Type', 'application/json')
    let method = ''
    try { method = JSON.parse(body).method } catch {}
    if (method === 'getblockchaininfo') {
      res.end(JSON.stringify({ result: { blocks: 5, headers: 5, verificationprogress: 1 }, error: null }))
    } else {
      res.end(JSON.stringify({ result: null, error: { message: `unknown method ${method}` } }))
    }
  })
})
server.listen(port, '127.0.0.1')
