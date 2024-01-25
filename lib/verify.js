import {name} from './name.js';
import {requiredAlgorithm} from './requiredAlgorithm.js';
import {createVerifier} from './createVerifier.js';

export function createVerifyCryptosuite() {
    return {
      name,
      requiredAlgorithm,
      createVerifier,
      createVerifyData: _createVerifyData,
      additionalHash
    };
  }

async function _createVerifyData({
    cryptosuite, document, proof, documentLoader
}){
    const options = {documentLoader};
    const proofHash = await hashCanonizedProof({document, proof, options});  
    const docHash = await canonize(document);
    const externalHash = cryptosuite.additionalHash;
    
    //concat: proofHash + docHash + externalHash
    return concat(concat(proofHash, docHash), externalHash)
}
