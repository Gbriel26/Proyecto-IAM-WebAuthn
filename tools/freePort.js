'use strict';

const net = require('net');

/** Devuelve un puerto TCP libre en loopback (para tests y benchmark). */
function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

module.exports = { getFreePort };
