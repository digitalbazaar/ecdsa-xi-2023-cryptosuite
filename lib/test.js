import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import jsigs from 'jsonld-signatures';
import { createCryptosuite } from './sign.js';
const {purposes: {AssertionProofPurpose}} = jsigs;
import {ecdsaMultikeyKeyPair} from '../test/mock-data.js'
import {loader} from '../test/documentLoader.js';
import {encode} from '@digitalbazaar/cborld';

// import the ECDSA key pair to use when signing
const publicKeyMultibase = 'zDnaekGZTbQBerwcehBSXLqAg6s55hVEBms1zFy89VHXtJSa9';
const secretKeyMultibase = 'z42tqZ5smVag3DtDhjY9YfVwTMyVHW6SCHJi2ZMrD23DGYS3';
const controller = `did:key:${publicKeyMultibase}`;
const keyId = `${controller}#${publicKeyMultibase}`;
const publicEcdsaMultikey = {
  '@context': 'https://w3id.org/security/multikey/v1',
  type: 'Multikey',
  controller: `did:key:${publicKeyMultibase}`,
  id: keyId,
  publicKeyMultibase
};
const keyPair = await EcdsaMultikey.from({...ecdsaMultikeyKeyPair});
const documentLoader = loader.build();

// create the unsigned credential
const unsignedCredential = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vdl/v1",
      "https://w3id.org/vdl/aamva/v1"
    ],
    "type": [
      "VerifiableCredential",
      "Pdf417DataIntegrityCredential"
    ],
    "issuer": "pdf417:issuer",
    "credentialStatus": {
      "type": "Pdf417StatusList",
      "index": 283749
    },
    "credentialSubject": {
      "type": "Pdf417Barcode",
    }
  };

let utf8Encode = new TextEncoder();
const additionalHash = utf8Encode.encode("6d721ae5d334cead832a8576bdd24d9a");

// create suite
const suite = new DataIntegrityProof({
  signer: keyPair.signer(),
  cryptosuite: createCryptosuite(additionalHash)
});

// create signed credential
const signedCredential = await jsigs.sign(unsignedCredential, {
  suite,
  purpose: new AssertionProofPurpose(),
  documentLoader
});


// verify the derived credential
const result = await jsigs.verify(signedCredential, {
  suite,
  purpose: new AssertionProofPurpose(),
  documentLoader
});

console.log(signedCredential);
console.log(result);
