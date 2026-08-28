/*
 * server.js -- tiny static web server for the NetBeans HTML5/JS project.
 *
 * Serves public_html so the demo and the two sample pages can be opened over
 * http:// instead of file:// (the extension then behaves exactly as it would
 * on a real website).
 *
 * Start with:  npm start      then open http://localhost:8383/
 * Uses only Node core modules, so no "npm install" is required.
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 8383;
const ROOT = path.join(__dirname, 'public_html');

const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.txt': 'text/plain; charset=utf-8'
};

const server = http.createServer((request, response) => {
    let pathname = decodeURIComponent(url.parse(request.url).pathname);
    if (pathname === '/') { pathname = '/index.html'; }

    // Resolve inside ROOT only - blocks ../../ traversal.
    const filePath = path.join(ROOT, path.normalize(pathname));
    if (!filePath.startsWith(ROOT)) {
        response.writeHead(403, {'Content-Type': 'text/plain'});
        return response.end('403 Forbidden');
    }

    fs.readFile(filePath, (error, content) => {
        if (error) {
            response.writeHead(404, {'Content-Type': 'text/html; charset=utf-8'});
            return response.end('<h1>404 - not found</h1><p>' + pathname + '</p>');
        }
        response.writeHead(200, {
            'Content-Type': MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
            'Cache-Control': 'no-cache'
        });
        response.end(content);
    });
});

server.listen(PORT, () => {
    console.log('Demo 4 server running on http://localhost:' + PORT + '/');
    console.log('Serving ' + ROOT);
});
