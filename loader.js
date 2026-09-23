import { register } from 'node:module';
import { pathToFileURL } from 'node:url';

const loaderCode = `
export async function resolve(specifier, context, nextResolve) {
  if (specifier === 'encoding') {
    return {
      shortCircuit: true,
      url: 'data:text/javascript,export const TextEncoder = globalThis.TextEncoder; export const atob = globalThis.atob;'
    };
  }
  if (specifier === 'crypto') {
    return {
      shortCircuit: true,
      url: 'data:text/javascript,import { webcrypto } from "node:crypto"; export const crypto = webcrypto;'
    };
  }
  if (specifier === 'log') {
    return {
      shortCircuit: true,
      url: 'data:text/javascript,export const logger = { debug: ()=>{}, info: ()=>{}, warn: ()=>{}, error: ()=>{} };'
    };
  }
  return nextResolve(specifier, context);
}
`;

register(`data:text/javascript,${encodeURIComponent(loaderCode)}`, pathToFileURL('./'));
await import('./test.js');
