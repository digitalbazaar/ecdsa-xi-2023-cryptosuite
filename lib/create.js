import {createHasher, hashCanonizedProof, stringToUtf8Bytes}
  from '@digitalbazaar/di-sd-primitives';
import {canonize} from './canonize.js';
import {concat} from './helper.js';
import {createVerifier} from './createVerifier.js';
import {name} from './name.js';
import {requiredAlgorithm} from './requiredAlgorithm.js';

export function createCryptosuite({extraInformation = ''} = {}) {
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
  const externalHash = cryptosuite.options.extraInformation;

  //canonize and hash proof
  const proofHash = await hashCanonizedProof({document, proof, options});

  //canonize and hash document
  const docCanon = await canonize(document);
  const hasher = createHasher();
  const docHash = await hasher.hash(stringToUtf8Bytes(docCanon));

  //current order of hashing: proof hash + document hash + external hash
  const hashConcat = concat(concat(proofHash, docHash), externalHash);

  return hashConcat;
}

