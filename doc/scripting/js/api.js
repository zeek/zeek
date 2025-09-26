// api.js
//
// HTTP API allowing to invoke any Zeek events and functions using a simple JSON payload.
//
// Triggering and intel match (this will log to intel.log)
//
//     $ curl --data-raw '{"args": [{"indicator": "50.3.2.1", "indicator_type": "Intel::ADDR", "where":"Intel::IN_ANYWHERE"}, []]}' \
//         http://localhost:8080/events/Intel::match
//
// Calling a Zeek function:
//
//     $ curl -XPOST --data '{"args": [1000]}' localhost:8080/functions/rand
//     {
//       "result": 730
//     }
//
const http = require('node:http');

// Light-weight safe-json-stringify replacement.
BigInt.prototype.toJSON = function () { return parseInt(this.toString()); };

const handleCall = (cb, req, res) => {
  const name = req.url.split('/').at(-1);
  const body = [];
  req.on('data', (chunk) => {
    body.push(chunk);
  }).on('end', () => {
    try {
      const parsed = JSON.parse(Buffer.concat(body).toString() || '{}');
      const args = parsed.args || [];
      const result = cb(name, args);
      res.writeHead(202);
      return res.end(`${JSON.stringify({ result: result }, null, 2)}\n`);
    } catch (err) {
      console.error(`error: ${err}`);
      res.writeHead(400);
      return res.end(`${JSON.stringify({ error: err.toString() })}\n`);
    }
  });
};

const server = http.createServer((req, res) => {
  if (req.method === 'POST') {
    if (req.url.startsWith('/events/')) {
      return handleCall(zeek.event, req, res);
    } else if (req.url.startsWith('/functions/')) {
      return handleCall(zeek.invoke, req, res);
    }
  }

  res.writeHead(404);
  return res.end();
});

const host = process.env.API_HOST || '127.0.0.1';
const port = parseInt(process.env.API_PORT || 8080, 10);

server.listen(port, host, () => {
  console.log(`Listening on ${host}:${port}...`);
});
