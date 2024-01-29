import {name} from './name.js';
import {requiredAlgorithm} from './requiredAlgorithm.js';
import {createVerifier} from './createVerifier.js';
import {concat} from './helper.js';
import {hashCanonizedProof, createHasher, stringToUtf8Bytes} from '@digitalbazaar/di-sd-primitives';
import {canonize} from './canonize.js';


export function createVerifyCryptosuite(extraInformation) {

    const additionalHash = extraInformation;
    return {
      name,
      requiredAlgorithm,
      createVerifier,
      createVerifyData: _createVerifyData,
      additionalHash
    };
  }

  async function _createVerifyData({
    cryptosuite, document, proof, documentLoader})
{

    const options = {documentLoader};
    const proofHash = await hashCanonizedProof({document, proof, options});  
    const externalHash = cryptosuite.additionalHash;
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
