import assert from 'node:assert';
import { base64toUint8Array, getJA4Fingerprint } from './util.js';

async function runTests() {
  console.log('Running tests...');

  // 1. Test base64toUint8Array
  console.log('Testing base64toUint8Array...');
  assert.strictEqual(base64toUint8Array(null).length, 0);
  assert.strictEqual(base64toUint8Array(undefined).length, 0);
  assert.strictEqual(base64toUint8Array(12345).length, 0);

  const sampleB64 = Buffer.from('Hello World').toString('base64');
  const arr = base64toUint8Array(sampleB64);
  assert.strictEqual(Buffer.from(arr).toString('utf-8'), 'Hello World');

  // 2. Test getJA4Fingerprint invalid buffer inputs
  console.log('Testing getJA4Fingerprint input validation...');
  await assert.rejects(
    async () => await getJA4Fingerprint(null, 'tcp'),
    /Invalid buffer provided/
  );
  await assert.rejects(
    async () => await getJA4Fingerprint("not a buffer", 'tcp'),
    /Invalid buffer provided/
  );

  // 3. Test truncated buffers at various lengths
  console.log('Testing getJA4Fingerprint buffer length boundary checks...');

  // Empty buffer
  await assert.rejects(
    async () => await getJA4Fingerprint(new Uint8Array(0), 'tcp'),
    /Buffer too short for TLS version and Client Random/
  );

  // Buffer shorter than 38 bytes (4 handshake header + 2 tls version + 32 client random)
  await assert.rejects(
    async () => await getJA4Fingerprint(new Uint8Array(30), 'tcp'),
    /Buffer too short for TLS version and Client Random/
  );

  // Buffer with valid TLS version + client random, but missing Session ID length
  const buf38 = new Uint8Array(38); // 4 skip + 34
  await assert.rejects(
    async () => await getJA4Fingerprint(buf38, 'tcp'),
    /Buffer too short for Session ID length/
  );

  // Buffer with Session ID length = 32, but truncated Session ID payload
  const bufSessionIdTrunc = new Uint8Array(39);
  bufSessionIdTrunc[38] = 32; // Session ID length = 32
  await assert.rejects(
    async () => await getJA4Fingerprint(bufSessionIdTrunc, 'tcp'),
    /Buffer too short for Session ID payload/
  );

  // Buffer with valid Session ID (0 length), but missing Cipher Suites length
  const bufCipherSuitesLenTrunc = new Uint8Array(39);
  bufCipherSuitesLenTrunc[38] = 0; // Session ID length = 0
  await assert.rejects(
    async () => await getJA4Fingerprint(bufCipherSuitesLenTrunc, 'tcp'),
    /Buffer too short for Cipher Suites length/
  );

  // Buffer with Cipher Suites length = 10, but truncated Cipher Suites payload
  const bufCipherSuitesTrunc = new Uint8Array(41);
  bufCipherSuitesTrunc[38] = 0; // Session ID length = 0
  // cipher suites length = 10 (0x000a) at index 39,40
  bufCipherSuitesTrunc[39] = 0x00;
  bufCipherSuitesTrunc[40] = 0x0a;
  await assert.rejects(
    async () => await getJA4Fingerprint(bufCipherSuitesTrunc, 'tcp'),
    /Buffer too short for Cipher Suites payload/
  );

  // Buffer with valid Cipher Suites (0 length), but missing Compression Methods length
  const bufCompLenTrunc = new Uint8Array(41);
  bufCompLenTrunc[38] = 0; // Session ID len = 0
  bufCompLenTrunc[39] = 0; // Cipher suites len = 0
  bufCompLenTrunc[40] = 0;
  await assert.rejects(
    async () => await getJA4Fingerprint(bufCompLenTrunc, 'tcp'),
    /Buffer too short for Compression Methods length/
  );

  // Buffer with Compression Methods length = 2, but truncated Compression Methods payload
  const bufCompTrunc = new Uint8Array(42);
  bufCompTrunc[38] = 0;
  bufCompTrunc[39] = 0;
  bufCompTrunc[40] = 0;
  bufCompTrunc[41] = 2; // Compression methods len = 2
  await assert.rejects(
    async () => await getJA4Fingerprint(bufCompTrunc, 'tcp'),
    /Buffer too short for Compression Methods payload/
  );

  // Buffer with Extensions length = 10, but truncated Extensions payload
  const bufExtTrunc = new Uint8Array(45);
  bufExtTrunc[38] = 0;
  bufExtTrunc[39] = 0;
  bufExtTrunc[40] = 0;
  bufExtTrunc[41] = 0; // Comp len = 0
  bufExtTrunc[42] = 0x00;
  bufExtTrunc[43] = 0x0a; // Extensions len = 10, but total length is only 45
  await assert.rejects(
    async () => await getJA4Fingerprint(bufExtTrunc, 'tcp'),
    /Buffer too short for Extensions payload/
  );

  // Buffer with extension inner length exceeding extension payload boundary
  const bufExtHeaderTrunc = new Uint8Array(48);
  bufExtHeaderTrunc[38] = 0;
  bufExtHeaderTrunc[39] = 0;
  bufExtHeaderTrunc[40] = 0;
  bufExtHeaderTrunc[41] = 0;
  bufExtHeaderTrunc[42] = 0x00;
  bufExtHeaderTrunc[43] = 0x04; // Extensions length = 4
  // Extension header at 44: extType = 0x0000 (SNI), extLength = 0x0010 (16 bytes > 4)
  bufExtHeaderTrunc[44] = 0x00;
  bufExtHeaderTrunc[45] = 0x00;
  bufExtHeaderTrunc[46] = 0x00;
  bufExtHeaderTrunc[47] = 0x10;
  await assert.rejects(
    async () => await getJA4Fingerprint(bufExtHeaderTrunc, 'tcp'),
    /Extension length exceeds extensions payload boundary/
  );

  // 4. Test valid ClientHello buffer
  console.log('Testing valid ClientHello buffer...');
  // Construct a minimal valid ClientHello
  // 4 bytes header skip
  // 2 bytes TLS version (0x0303 = TLS 1.2)
  // 32 bytes client random
  // 1 byte Session ID length (0)
  // 2 bytes Cipher Suites length (4 bytes = 2 ciphers: 0x002f, 0x0035)
  // 4 bytes Ciphers (0x002f, 0x0035)
  // 1 byte Compression Methods length (1)
  // 1 byte Compression Method (0)
  // 2 bytes Extensions length (0)
  const validBuf = new Uint8Array(4 + 2 + 32 + 1 + 2 + 4 + 1 + 1 + 2);
  const dv = new DataView(validBuf.buffer);
  dv.setUint16(4, 0x0303); // TLS 1.2 -> '12'
  validBuf[38] = 0; // Session ID len
  dv.setUint16(39, 4); // Cipher suites len
  dv.setUint16(41, 0x002f);
  dv.setUint16(43, 0x0035);
  validBuf[45] = 1; // Compression methods len
  validBuf[46] = 0; // Compression method
  dv.setUint16(47, 0); // Extensions len

  const ja4 = await getJA4Fingerprint(validBuf, 'tcp');
  console.log('Calculated JA4:', ja4);
  assert.ok(ja4.startsWith('t12i020000_'), `Unexpected JA4 prefix: ${ja4}`);

  console.log('All tests passed successfully!');
}

runTests().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
