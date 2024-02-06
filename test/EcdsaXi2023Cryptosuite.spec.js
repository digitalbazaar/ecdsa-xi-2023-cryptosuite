/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import {expect} from 'chai';

import jsigs from 'jsonld-signatures';
const {purposes: {AssertionProofPurpose}} = jsigs;

import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {
  credential,
  ecdsaMultikeyKeyPair,
  ecdsaSecp256KeyPair
} from './mock-data.js';
import {createCryptosuite} from '../lib/index.js';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';

import {loader} from './documentLoader.js';

const documentLoader = loader.build();
const extraInformation = new Uint8Array([
  12, 52, 75, 63, 74, 85, 21, 5, 62, 10,
  12, 52, 75, 63, 74, 85, 21, 5, 62, 100,
  12, 52, 75, 63, 74, 85, 21, 5, 62, 100,
  12, 52, 75, 63, 74, 85, 21, 5, 62, 100,
  12, 52, 75, 63, 74, 85, 21, 5, 62, 100,
  12, 52, 75, 63, 74, 85, 21, 5, 62, 100,
  12, 52, 75, 63
]);
const ecdsaXi2023Cryptosuite = createCryptosuite({extraInformation});

describe('EcdsaXi2023Cryptosuite', () => {
  describe('exports', () => {
    it('it should have proper exports', async () => {
      should.exist(ecdsaXi2023Cryptosuite);
      ecdsaXi2023Cryptosuite.name.should.equal('ecdsa-xi-2023');
      ecdsaXi2023Cryptosuite.requiredAlgorithm.should.eql(['P-256', 'P-384']);
      ecdsaXi2023Cryptosuite.canonize.should.be.a('function');
      ecdsaXi2023Cryptosuite.createVerifier.should.be.a('function');
    });
  });

  describe('canonize()', () => {
    it('should canonize using URDNA2015 w/ n-quads', async () => {
      const unsignedCredential = JSON.parse(JSON.stringify(credential));

      let result;
      let error;
      try {
        result = await ecdsaXi2023Cryptosuite.canonize(
          unsignedCredential, {documentLoader});
      } catch(e) {
        error = e;
      }

      expect(error).to.not.exist;
      expect(result).to.exist;
      /* eslint-disable max-len */
      const expectedResult = `<https://example.edu/credentials/1872> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://example.org/examples#AlumniCredential> .
<https://example.edu/credentials/1872> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .
<https://example.edu/credentials/1872> <https://www.w3.org/2018/credentials#credentialSubject> <https://example.edu/students/alice> .
<https://example.edu/credentials/1872> <https://www.w3.org/2018/credentials#issuanceDate> "2010-01-01T19:23:24Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
<https://example.edu/credentials/1872> <https://www.w3.org/2018/credentials#issuer> <https://example.edu/issuers/565049> .
<https://example.edu/students/alice> <https://schema.org/alumniOf> "Example University" .\n`;
      /* eslint-enable max-len */
      result.should.equal(expectedResult);
    });
  });

  describe('createVerifier()', () => {
    it('should create a verifier with ECDSA Multikey', async () => {
      let verifier;
      let error;
      try {
        verifier = await ecdsaXi2023Cryptosuite.createVerifier({
          verificationMethod: {...ecdsaMultikeyKeyPair}
        });
      } catch(e) {
        error = e;
      }

      expect(error).to.not.exist;
      expect(verifier).to.exist;
      verifier.algorithm.should.equal('P-256');
      verifier.id.should.equal('https://example.edu/issuers/565049#zDnaekGZTb' +
        'QBerwcehBSXLqAg6s55hVEBms1zFy89VHXtJSa9');
      verifier.verify.should.be.a('function');
    });

    it('should create a verifier with EcdsaSecp256r1VerificationKey2019',
      async () => {
        let verifier;
        let error;
        const keyPair = await EcdsaMultikey.from({...ecdsaSecp256KeyPair});
        try {
          verifier = await ecdsaXi2023Cryptosuite.createVerifier({
            verificationMethod: keyPair
          });
        } catch(e) {
          error = e;
        }

        expect(error).to.not.exist;
        expect(verifier).to.exist;
        verifier.algorithm.should.equal('P-256');
        verifier.id.should.equal('https://example.edu/issuers/565049#zDnaekG' +
          'ZTbQBerwcehBSXLqAg6s55hVEBms1zFy89VHXtJSa9');
        verifier.verify.should.be.a('function');
      });

    it('should fail to create a verifier w/ unsupported key type', async () => {
      let verifier;
      let error;
      const keyPair = await EcdsaMultikey.from({...ecdsaSecp256KeyPair});
      keyPair.type = 'BadKeyType';
      try {
        verifier = await ecdsaXi2023Cryptosuite.createVerifier({
          verificationMethod: keyPair
        });
      } catch(e) {
        error = e;
      }

      expect(error).to.exist;
      expect(verifier).to.not.exist;
      error.message.should.equal('Unsupported key type "BadKeyType".');
    });
  });

  describe('sign()', () => {
    it('should sign a document', async () => {
      const unsignedCredential = JSON.parse(JSON.stringify(credential));
      const keyPair = await EcdsaMultikey.from({...ecdsaMultikeyKeyPair});
      const date = '2023-03-01T21:29:24Z';
      const suite = new DataIntegrityProof({
        signer: keyPair.signer(), date, cryptosuite: ecdsaXi2023Cryptosuite
      });

      let error;
      try {
        await jsigs.sign(unsignedCredential, {
          suite,
          purpose: new AssertionProofPurpose(),
          documentLoader
        });
      } catch(e) {
        error = e;
      }

      expect(error).to.not.exist;
    });

    it('should fail to sign with undefined term', async () => {
      const unsignedCredential = JSON.parse(JSON.stringify(credential));
      unsignedCredential.undefinedTerm = 'foo';

      const keyPair = await EcdsaMultikey.from({...ecdsaMultikeyKeyPair});
      const date = '2023-03-01T21:29:24Z';
      const suite = new DataIntegrityProof({
        signer: keyPair.signer(), date, cryptosuite: ecdsaXi2023Cryptosuite
      });

      let error;
      try {
        await jsigs.sign(unsignedCredential, {
          suite,
          purpose: new AssertionProofPurpose(),
          documentLoader
        });
      } catch(e) {
        error = e;
      }

      expect(error).to.exist;
      expect(error.name).to.equal('jsonld.ValidationError');
    });

    it('should fail to sign with relative type URL', async () => {
      const unsignedCredential = JSON.parse(JSON.stringify(credential));
      unsignedCredential.type.push('UndefinedType');

      const keyPair = await EcdsaMultikey.from({...ecdsaMultikeyKeyPair});
      const date = '2023-03-01T21:29:24Z';
      const suite = new DataIntegrityProof({
        signer: keyPair.signer(), date, cryptosuite: ecdsaXi2023Cryptosuite
      });

      let error;
      try {
        await jsigs.sign(unsignedCredential, {
          suite,
          purpose: new AssertionProofPurpose(),
          documentLoader
        });
      } catch(e) {
        error = e;
      }

      expect(error).to.exist;
      expect(error.name).to.equal('jsonld.ValidationError');
    });

    it('should fail to sign with non-bytes extraInformation', async () => {
      const unsignedCredential = JSON.parse(JSON.stringify(credential));
      unsignedCredential.type.push('UndefinedType');

      const badCryptosuite = createCryptosuite(100);
      const keyPair = await EcdsaMultikey.from({...ecdsaMultikeyKeyPair});
      const date = '2023-03-01T21:29:24Z';
      const suite = new DataIntegrityProof({
        signer: keyPair.signer(), date, cryptosuite: badCryptosuite
      });

      let error;
      try {
        await jsigs.sign(unsignedCredential, {
          suite,
          purpose: new AssertionProofPurpose(),
          documentLoader
        });
      } catch(e) {
        error = e;
      }

      expect(error).to.exist;
      expect(error.name).to.equal('jsonld.ValidationError');
    });

    it('should fail to sign with incorrect signer algorithm', async () => {
      const keyPair = await EcdsaMultikey.from({...ecdsaMultikeyKeyPair});
      const date = '2023-03-01T21:29:24Z';
      const signer = keyPair.signer();
      signer.algorithm = 'wrong-algorithm';

      let error;
      try {
        new DataIntegrityProof({
          signer, date, cryptosuite: ecdsaXi2023Cryptosuite
        });
      } catch(e) {
        error = e;
      }

      const errorMessage = `The signer's algorithm "${signer.algorithm}" ` +
        `is not a supported algorithm for the cryptosuite. The supported ` +
        `algorithms are: ` +
        `"${ecdsaXi2023Cryptosuite.requiredAlgorithm.join(', ')}".`;

      expect(error).to.exist;
      expect(error.message).to.equal(errorMessage);
    });
  });

  describe('verify()', () => {
    let signedCredential;

    before(async () => {
      const unsignedCredential = JSON.parse(JSON.stringify(credential));

      const keyPair = await EcdsaMultikey.from({...ecdsaMultikeyKeyPair});
      const date = '2023-03-01T21:29:24Z';
      const suite = new DataIntegrityProof({
        signer: keyPair.signer(), date, cryptosuite: ecdsaXi2023Cryptosuite
      });

      signedCredential = await jsigs.sign(unsignedCredential, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });
    });

    it('should verify a document', async () => {
      const suite = new DataIntegrityProof({
        cryptosuite: ecdsaXi2023Cryptosuite
      });
      const result = await jsigs.verify(signedCredential, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });

      expect(result.verified).to.be.true;
    });

    it('should fail verification if "proofValue" is not string', async () => {
      const suite = new DataIntegrityProof({
        cryptosuite: ecdsaXi2023Cryptosuite
      });
      const signedCredentialCopy =
        JSON.parse(JSON.stringify(signedCredential));
      // intentionally modify proofValue type to not be string
      signedCredentialCopy.proof.proofValue = {};

      const result = await jsigs.verify(signedCredentialCopy, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });

      const {error} = result.results[0];

      expect(result.verified).to.be.false;
      expect(error.name).to.equal('TypeError');
      expect(error.message).to.equal(
        'The proof does not include a valid "proofValue" property.'
      );
    });

    it('should fail verification if "proofValue" is not given', async () => {
      const suite = new DataIntegrityProof({
        cryptosuite: ecdsaXi2023Cryptosuite
      });
      const signedCredentialCopy =
        JSON.parse(JSON.stringify(signedCredential));
      // intentionally modify proofValue to be undefined
      signedCredentialCopy.proof.proofValue = undefined;

      const result = await jsigs.verify(signedCredentialCopy, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });

      const {error} = result.results[0];

      expect(result.verified).to.be.false;
      expect(error.name).to.equal('TypeError');
      expect(error.message).to.equal(
        'The proof does not include a valid "proofValue" property.'
      );
    });

    it('should fail verification if proofValue string does not start with "z"',
      async () => {
        const suite = new DataIntegrityProof({
          cryptosuite: ecdsaXi2023Cryptosuite
        });
        const signedCredentialCopy =
          JSON.parse(JSON.stringify(signedCredential));
        // intentionally modify proofValue to not start with 'z'
        signedCredentialCopy.proof.proofValue = 'a';

        const result = await jsigs.verify(signedCredentialCopy, {
          suite,
          purpose: new AssertionProofPurpose(),
          documentLoader
        });

        const {errors} = result.error;

        expect(result.verified).to.be.false;
        expect(errors[0].name).to.equal('Error');
        expect(errors[0].message).to.include('base58btc');
      }
    );

    it('should fail verification if proof type is not DataIntegrityProof',
      async () => {
        const suite = new DataIntegrityProof({
          cryptosuite: ecdsaXi2023Cryptosuite
        });
        const signedCredentialCopy =
          JSON.parse(JSON.stringify(signedCredential));
        // intentionally modify proof type to be InvalidSignature2100
        signedCredentialCopy.proof.type = 'InvalidSignature2100';

        const result = await jsigs.verify(signedCredentialCopy, {
          suite,
          purpose: new AssertionProofPurpose(),
          documentLoader
        });

        const {errors} = result.error;

        expect(result.verified).to.be.false;
        expect(errors[0].name).to.equal('NotFoundError');
      });
  });
});
