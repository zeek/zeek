// server.js
import WebSocket, { WebSocketServer } from 'ws';

const wss = new WebSocketServer({ port: 8080 });

wss.on('connection', (ws, req) => {
  ws.on('error', console.error);
  ws.on('close', () => { console.log('%s: gone', ws.zeek.app); });

  ws.on('message', function message(data) {
      console.log('%s: received: %s', ws.zeek.app, data);
  });

  let topics = ['zeek.bridge.test'];
  let app = req.headers['x-application-name'] || '<unknown application>'
  ws.zeek = {
    app: app,
    topics: topics,
  };

  console.log(`${app}: connected, sending topics array ${JSON.stringify(topics)}`);
  ws.send(JSON.stringify(topics));
});
