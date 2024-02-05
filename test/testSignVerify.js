import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {createCryptosuite} from '../lib/create.js';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {ecdsaMultikeyKeyPair} from './mock-data.js';
import jsigs from 'jsonld-signatures';
import {loader} from './documentLoader.js';

const {purposes: {AssertionProofPurpose}} = jsigs;

// import the ECDSA key pair to use when signing
const publicKeyMultibase = 'zDnaekGZTbQBerwcehBSXLqAg6s55hVEBms1zFy89VHXtJSa9';
const controller = `did:key:${publicKeyMultibase}`;

const keyPair = await EcdsaMultikey.from({...ecdsaMultikeyKeyPair});
const documentLoader = loader.build();

// create the unsigned credential
const unsignedCredential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    {
      '@protected': true,
      AlumniCredential: 'urn:example:AlumniCredential',
      alumniOf: 'https://schema.org#alumniOf'
    },
    'https://w3id.org/security/data-integrity/v2'
  ],
  id: 'urn:uuid:98c5cffc-efa2-43e3-99f5-01e8ef404be0',
  type: ['VerifiableCredential', 'AlumniCredential'],
  issuer: controller,
  issuanceDate: '2010-01-01T19:23:24Z',
  credentialSubject: {
    id: 'urn:uuid:d58b2365-0951-4373-96c8-e886d61829f2',
    alumniOf: 'Example University'
  }
};

const extraInformation = new Uint8Array([12, 52, 75, 63, 74, 85,
  21, 5, 62, 100]);

// create suite
const suite = new DataIntegrityProof({
  signer: keyPair.signer(),
  cryptosuite: createCryptosuite({extraInformation})
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
