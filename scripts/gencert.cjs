const forge = require('node-forge');
const fs = require('fs');
const path = require('path');
const pki = forge.pki;

const keys = pki.rsa.generateKeyPair(2048);
const cert = pki.createCertificate();
cert.publicKey = keys.publicKey;
cert.serialNumber = Date.now().toString(16) + Math.random().toString(16).slice(2, 10);
cert.validity.notBefore = new Date();
cert.validity.notAfter = new Date();
cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1);

const attrs = [
  { name: 'commonName', value: 'localhost' },
  { name: 'organizationName', value: 'Sentinel Oracle' }
];
cert.setSubject(attrs);
cert.setIssuer(attrs);

cert.setExtensions([
  { name: 'subjectAltName', altNames: [{ type: 2, value: 'localhost' }, { type: 7, ip: '127.0.0.1' }] },
  { name: 'basicConstraints', cA: true },
  { name: 'keyUsage', keyCertSign: true, digitalSignature: true, keyEncipherment: true },
  { name: 'extKeyUsage', serverAuth: true }
]);

cert.sign(keys.privateKey, forge.md.sha256.create());

const dir = path.join(require('os').homedir(), '.sentinel-oracle');
fs.writeFileSync(path.join(dir, 'server.cert'), pki.certificateToPem(cert));
fs.writeFileSync(path.join(dir, 'server.key'), pki.privateKeyToPem(keys.privateKey));

console.log('OK: ' + path.join(dir, 'server.cert') + ' (' + fs.statSync(path.join(dir, 'server.cert')).size + ' bytes)');
console.log('OK: ' + path.join(dir, 'server.key') + ' (' + fs.statSync(path.join(dir, 'server.key')).size + ' bytes)');
