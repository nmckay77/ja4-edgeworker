import { TextEncoder, atob } from 'encoding';
import { crypto } from 'crypto';
import { logger } from 'log';

// Enable for extra debug code
const DEBUG_MODE = false;

// Mapping of TLS versions to their JA4 representation
const TLS_MAPPER = {
  '0x0002': 's2', // SSL 2.0  
  '0x0300': 's3', // SSL 3.0
  '0x0301': '10', // TLS 1.0
  '0x0302': '11', // TLS 1.1
  '0x0303': '12', // TLS 1.2
  '0x0304': '13'  // TLS 1.3
};

// Set of GREASE (Generate Random Extensions And Sustain Extensibility) values
const GREASE_VALUES = new Set([
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a,
  0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada,
  0xeaea, 0xfafa
]);

/**
 * Converts a base64 encoded string to a Uint8Array.
 * @param {string} base64_string - The base64 encoded string to convert.
 * @returns {Uint8Array} The resulting Uint8Array.
 */
export function base64toUint8Array(base64_string) {
  const binary_string = atob(base64_string);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes;
}

/**
 * Calculates the SHA-256 hash of the input data and returns the first 12 characters.
 * @param {string} data - The input data to hash.
 * @returns {string} The first 12 characters of the SHA-256 hash.
 */
async function truncatedHash(data) {
  const encoder = new TextEncoder();
  const encoded = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 12);
}

/**
 * Helper function to check if a character is printable ASCII.
 * @param {number} charCode - The character code to check.
 * @returns {boolean} True if the character is printable ASCII, false otherwise.
 */
function isPrintableAscii(charCode) {
  return charCode >= 0x20 && charCode <= 0x7E;
}

/**
 * Calculates the JA4 fingerprint and its variants from the ClientHello data.
 * @param {Uint8Array} buffer - The ClientHello data as a Uint8Array.
 * @param {string} proto - The protocol ('quic' or 'tcp').
 * @returns {string} The calculated JA4 fingerprint.
 */
export async function getJA4Fingerprint(buffer, proto) {
  const dataView = new DataView(buffer.buffer);

  try {
    let currentIndex = 4; // Skip handshake type and length

    // Extract TLS version
    const tlsVersion = `0x${dataView.getUint16(currentIndex).toString(16).padStart(4, '0')}`;
    let tlsMappedVersion = TLS_MAPPER[tlsVersion] || '00';
    currentIndex += 34; // Skip over TLS version and client random

    // Skip session ID
    const sessionIDLength = dataView.getUint8(currentIndex);
    currentIndex += 1 + sessionIDLength;

    // Extract cipher suites
    const cipherSuitesLength = dataView.getUint16(currentIndex);
    currentIndex += 2;
    const cipherSuites = [];
    for (let i = 0; i < cipherSuitesLength; i += 2) {
      const cipher = dataView.getUint16(currentIndex + i);
      if (!GREASE_VALUES.has(cipher)) {
        cipherSuites.push(cipher.toString(16).padStart(4, '0'));
      }
    }
    currentIndex += cipherSuitesLength;

    // Skip compression methods
    const compressionMethodsLength = dataView.getUint8(currentIndex);
    currentIndex += 1 + compressionMethodsLength;

    // Process extensions
    const extensionsLength = dataView.getUint16(currentIndex);
    currentIndex += 2;
    const extensionsList = [];
    let sni = 'i';
    let alpn = '00'; // Default value if no ALPN extension or values
    const signatureAlgorithms = [];
    const supportedVersions = [];

    const extensionsEndIndex = currentIndex + extensionsLength;
    while (currentIndex < extensionsEndIndex) {
      const extType = dataView.getUint16(currentIndex);
      const extLength = dataView.getUint16(currentIndex + 2);
      currentIndex += 4;

      if (!GREASE_VALUES.has(extType)) {
        const extTypeHex = extType.toString(16).padStart(4, '0');
        extensionsList.push(extTypeHex);

        if (extType === 0x0000) { // SNI
          sni = 'd';
        } else if (extType === 0x0010) { // ALPN
          const alpnListLength = dataView.getUint16(currentIndex);
          let alpnOffset = currentIndex + 2;
          const alpnEndOffset = alpnOffset + alpnListLength;
          
          if (alpnOffset < alpnEndOffset) {
            const protocolLength = dataView.getUint8(alpnOffset);
            alpnOffset++;

            if (protocolLength > 0) {
              const firstChar = dataView.getUint8(alpnOffset);
              const lastChar = dataView.getUint8(alpnOffset + protocolLength - 1);

              if (isPrintableAscii(firstChar) && isPrintableAscii(lastChar)) {
                alpn = String.fromCharCode(firstChar) + String.fromCharCode(lastChar);
              } else {
                alpn = ((firstChar >> 4) & 0x0F).toString(16) + (lastChar & 0x0F).toString(16);
              }
            }
          }
        } else if (extType === 0x002b) { // Supported Versions
          const supportedVersionsLength = dataView.getUint8(currentIndex);
          for (let i = 0; i < supportedVersionsLength; i += 2) {
            const version = dataView.getUint16(currentIndex + 1 + i);
            if (!GREASE_VALUES.has(version)) {
              supportedVersions.push(version);
            }
          }
        } else if (extType === 0x000d) { // Signature Algorithms
          const sigAlgLength = dataView.getUint16(currentIndex);
          for (let i = 0; i < sigAlgLength; i += 2) {
            const alg = dataView.getUint16(currentIndex + 2 + i);
            if (!GREASE_VALUES.has(alg)) {
              signatureAlgorithms.push(alg.toString(16).padStart(4, '0'));
            }
          }
        }
      }
      currentIndex += extLength;
    }

    // Determine the highest supported version
    if (supportedVersions.length > 0) {
      const highestSupportedVersion = `0x${supportedVersions.sort((a, b) => b - a)[0].toString(16).padStart(4, '0')}`;
      tlsMappedVersion = TLS_MAPPER[highestSupportedVersion] || '00';
    }

    // Calculate JA4 components
    const numCiphers = cipherSuites.length.toString().padStart(2, '0');
    const numExtensions = extensionsList.length.toString().padStart(2, '0');

    // Sort ciphers and prepare for hashing
    cipherSuites.sort();
    const cipherSuitesString = cipherSuites.join(',');
    const ja4CipherHash = await truncatedHash(cipherSuitesString);

    // Prepare extensions for hashing
    const hashExtensions = extensionsList.filter(ext => ext !== '0000' && ext !== '0010').sort();
    let extensionHashInput = hashExtensions.join(',');
    if (signatureAlgorithms.length > 0) {
      extensionHashInput += '_' + signatureAlgorithms.join(',');
    }
    const ja4ExtensionHash = await truncatedHash(extensionHashInput);

    const ptype = proto === 'quic' ? 'q' : 't';

    // Construct JA4 strings
    const ja4Base = `${ptype}${tlsMappedVersion}${sni}${numCiphers}${numExtensions}${alpn}`;
    const ja4 = `${ja4Base}_${ja4CipherHash}_${ja4ExtensionHash}`;
    const ja4_r = `${ja4Base}_${cipherSuitesString}_${extensionHashInput}`;
    
    logger.debug(`JA4: ${ja4}`);
    logger.debug(`JA4_r: ${ja4_r}`);

    if (DEBUG_MODE) {
      // Calculate JA4_o and JA4_ro
      const originalExtensions = extensionsList.filter(ext => ext !== '0000' && ext !== '0010');
      const originalExtensionHashInput = originalExtensions.join(',') + (signatureAlgorithms.length > 0 ? '_' + signatureAlgorithms.join(',') : '');
      const ja4OriginalExtensionHash = await truncatedHash(originalExtensionHashInput);

      const ja4_ro = `${ja4Base}_${cipherSuitesString}_${extensionsList.join(',')}_${signatureAlgorithms.join(',')}`;
      const ja4_o = `${ja4Base}_${ja4CipherHash}_${ja4OriginalExtensionHash}`;
    
      logger.debug(`JA4_ro: ${ja4_ro}`);
      logger.debug(`JA4_o: ${ja4_o}`);
    }

    return ja4;
  } catch (error) {
    logger.error(`Error in getJA4Fingerprint: ${error.message}`);
    throw error;
  }
}