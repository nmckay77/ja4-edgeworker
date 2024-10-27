import * as util from './util.js';
import { logger } from 'log';

/**
 * Calculates the JA4 fingerprint for a client request.
 * 
 * This function is triggered on client request and performs the following:
 * 1. Retrieves the ClientHello data from PMUSER_TLS_CLIENT_HELLO.
 * 2. Determines the protocol (QUIC or TCP) based on if PMUSER_QUIC_VERSION is set.
 * 3. Calculates the JA4 fingerprint using the ClientHello data and protocol.
 * 4. Saves the calculated fingerprint in a PMUSER_JA4_FINGERPRINT
 * 
 * @param {Object} request - The client request object.
 * @returns {string|undefined} The calculated JA4 fingerprint, or undefined if an error occurs.
 */
export async function onClientRequest(request) {
  // Retrieve the Client Hello data from the request
  const client_hello = request.getVariable('PMUSER_TLS_CLIENT_HELLO');
  if (!client_hello) {
    logger.info("No ClientHello");
    return;
  }
  
  // Convert the base64 encoded Client Hello to a Uint8Array
  const buffer = util.base64toUint8Array(client_hello);

  // Determine the protocol (QUIC or TCP) based on QUIC version which is only set for QUIC connections.
  const quic_version = request.getVariable('PMUSER_QUIC_VERSION');
  const proto = (quic_version) ? "quic" : "tcp";

  try {
    // Calculate the JA4 fingerprint
    const JA4_fingerprint = await util.getJA4Fingerprint(buffer, proto);

    // Store the calculated fingerprint in a variable for later use in Property Manager
    request.setVariable('PMUSER_JA4_FINGERPRINT', JA4_fingerprint);
    return JA4_fingerprint;
  } catch (error) {
    logger.error(`Error calculating JA4: ${error.message}`);
  }
}