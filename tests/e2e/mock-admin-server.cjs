const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const port = Number(process.argv[2] || process.env.E2E_PORT || 4173);
const rootDir = path.resolve(__dirname, '..', '..');
const adminDir = path.join(rootDir, 'static', 'admin');

const mime = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
};

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'content-type': mime['.json'],
    'cache-control': 'no-store',
  });
  res.end(body);
}

function sendFile(res, filePath) {
  fs.readFile(filePath, (err, content) => {
    if (err) {
      sendJson(res, 404, { code: 'NOT_FOUND', message: 'file not found' });
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'content-type': mime[ext] || 'application/octet-stream',
      'cache-control': 'no-store',
    });
    res.end(content);
  });
}

function safeJoin(baseDir, suffix) {
  const resolved = path.resolve(baseDir, suffix);
  if (!resolved.startsWith(baseDir)) {
    return null;
  }
  return resolved;
}

const server = http.createServer((req, res) => {
  const reqUrl = new URL(req.url || '/', 'http://127.0.0.1');
  const pathname = reqUrl.pathname;

  if (pathname === '/' || pathname === '/healthz') {
    sendJson(res, 200, { ok: true });
    return;
  }

  if (pathname === '/admin' || pathname === '/admin/') {
    sendFile(res, path.join(adminDir, 'index.html'));
    return;
  }

  if (pathname === '/admin/login' || pathname === '/admin/login/') {
    sendFile(res, path.join(adminDir, 'login.html'));
    return;
  }

  if (pathname.startsWith('/static/admin/')) {
    const rel = pathname.replace('/static/admin/', '');
    const target = safeJoin(adminDir, rel);
    if (!target) {
      sendJson(res, 400, { code: 'INVALID_PATH', message: 'invalid path' });
      return;
    }
    sendFile(res, target);
    return;
  }

  sendJson(res, 404, { code: 'NOT_FOUND', message: 'route not found' });
});

server.listen(port, '127.0.0.1', () => {
  console.log(`[e2e-mock-server] listening on http://127.0.0.1:${port}`);
});

const close = () => {
  server.close(() => process.exit(0));
};
process.on('SIGINT', close);
process.on('SIGTERM', close);
