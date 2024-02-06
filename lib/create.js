/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import {createHasher, hashCanonizedProof, stringToUtf8Bytes}
  from '@digitalbazaar/di-sd-primitives';
import {canonize} from './canonize.js';
import {concat} from './helpers.js';
import {createVerifier} from './createVerifier.js';
import {name} from './name.js';
import {requiredAlgorithm} from './requiredAlgorithm.js';

export function createCryptosuite({extraInformation = new Uint8Array()} = {}) {
  const options = {extraInformation};
  return {
    name,
    canonize,
    requiredAlgorithm,
    createVerifier,
    createVerifyData: _createSignData,
    options
  };
}

async function _createSignData({cryptosuite, document, proof, documentLoader}) {
  const options = {documentLoader};

  // create hash from `extraInformation`
  const hasher = createHasher();
  const externalHash = await hasher.hash(cryptosuite.options.extraInformation);

  // canonize and hash proof
  const proofHash = await hashCanonizedProof({document, proof, options});

  // canonize and hash document
  const docCanon = await canonize(document);
  const docHash = await hasher.hash(stringToUtf8Bytes(docCanon));

  // current order of hashing: proof hash + document hash + external hash
  const hashConcat = concat(proofHash, docHash, externalHash);

  return hashConcat;
}

