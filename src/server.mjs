// Long-lived local server (node src/server.mjs)
import http from 'node:http';
import { handle } from './handler.mjs';

const PORT = Number(process.env.PORT || 8080);
const server = http.createServer((req, res) => {
  handle(req, res).catch((err) => {
    if (!res.headersSent) {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ decision: 'REJECT', reason_code: 'INTERNAL_ERROR' }));
    }
    console.error('handler error', err?.message);
  });
});

server.headersTimeout = 70_000;
server.requestTimeout = 65_000;
server.listen(PORT, () => {
  console.log(JSON.stringify({
    up: true, port: PORT,
    secret: process.env.AGENT_GAMES_HMAC_SECRET ? 'set' : 'MISSING',
    encoding: (process.env.SIGNATURE_ENCODING || 'hex'),
    store: process.env.SEEN_SET_BACKEND || 'file',
  }));
});
