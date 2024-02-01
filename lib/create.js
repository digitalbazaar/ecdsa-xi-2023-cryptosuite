import {name} from './name.js';
import {requiredAlgorithm} from './requiredAlgorithm.js';
import {canonize} from './canonize.js';
import jsonld from 'jsonld';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {hashCanonizedProof, createHasher, stringToUtf8Bytes} from '@digitalbazaar/di-sd-primitives';
import {concat} from './helper.js';
import {createVerifier} from './createVerifier.js';

//TODO - need two different kinds?
export function createCryptosuite({extraInformation=''}={}) 
{
    const options = {extraInformation};
    return {
      name,
      requiredAlgorithm,
      createVerifier,
      createVerifyData: _createSignData,
      options
    };
}

function _throwSignUsageError() {
    throw new Error('This cryptosuite must only be used with "sign".');
}

async function _createSignData({
    cryptosuite, document, proof, documentLoader})
{

    const options = {documentLoader};
    const proofHash = await hashCanonizedProof({document, proof, options});  
    const externalHash = cryptosuite.options.extraInformation;
    const docCanon = await canonize(document);
    
    const hasher = createHasher();
    const docHash = await hasher.hash(stringToUtf8Bytes(docCanon));

    console.log(docHash);
    console.log(proofHash);
    console.log(externalHash);

    const hashConcat = concat(concat(proofHash, docHash), externalHash);
    console.log(hashConcat);

    return hashConcat
}

