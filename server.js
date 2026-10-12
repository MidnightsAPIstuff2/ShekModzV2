// Local dev only: node server.js  (Vercel uses api/index.js instead)
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const handler = require('./lib');
const PUBLIC = path.join(__dirname, 'public');
http.createServer((req, res) => {
  if (req.url.startsWith('/api/')) return handler(req, res);
  let rel = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(PUBLIC, rel));
  if (!file.startsWith(PUBLIC + path.sep)) { res.statusCode = 403; return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.statusCode = 404; return res.end('Not found'); }
    res.setHeader('Content-Type', file.endsWith('.html') ? 'text/html; charset=utf-8' : 'application/octet-stream');
    res.end(data);
  });
}).listen(process.env.PORT || 3000, () => console.log('Shek Modz on http://localhost:' + (process.env.PORT || 3000)));
