import {name} from './name.js';
import {requiredAlgorithm} from './requiredAlgorithm.js';
import {canonize} from './canonize.js';
import jsonld from 'jsonld';


//TODO - need two different kinds?
export function createSignCryptosuite(extraInformation) 
{
    const additionalHash = extraInformation;
    return {
      name,
      requiredAlgorithm,
      createVerifier: _throwSignUsageError,
      createVerifyData: _createSignData,
      additionalHash
    };
}

function _throwSignUsageError() {
    throw new Error('This cryptosuite must only be used with "sign".');
}

async function _createSignData({
    cryptosuite, document, proof, documentLoader})
{

    const options = {documentLoader};
    const proofHash = await canonize(proof);  
    //const docHash = await canonize(document);
    const externalHash = cryptosuite.additionalHash;
    const docHash = await canonize(document);
    console.log(externalHash)
    
    //dummy values for testing - unsure how to canonize
    //const proofHash = "1b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014";
    //const docHash = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";

    //concat" proofHash + docHash + externalHash
    return concat(concat(proofHash, docHash), externalHash)
}

function concat(b1, b2)
{
    const rval = new Uint8Array(b1.length + b2.length);
    rval.set(b1, 0);
    rval.set(b2, b1.length);
    return rval;
}