/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import {
  controllerDocEcdsaMultikey,
  ecdsaMultikeyKeyPair,
  mockPublicEcdsaMultikey,
} from './mock-data.js';
import dataIntegrityContext from '@digitalbazaar/data-integrity-context';
import multikeyContext from '@digitalbazaar/multikey-context';
import {securityLoader} from '@digitalbazaar/security-document-loader';

export const loader = securityLoader();

loader.addStatic(
  ecdsaMultikeyKeyPair.controller,
  controllerDocEcdsaMultikey
);
loader.addStatic(
  mockPublicEcdsaMultikey.id,
  mockPublicEcdsaMultikey
);

loader.addStatic(
  dataIntegrityContext.constants.CONTEXT_URL,
  dataIntegrityContext.contexts.get(dataIntegrityContext.constants.CONTEXT_URL)
);

loader.addStatic(
  multikeyContext.constants.CONTEXT_URL,
  multikeyContext.contexts.get(multikeyContext.constants.CONTEXT_URL)
);

const bogusContext = {
  '@context': {
    id: '@id',
    type: '@type',
    '@protected': true,
    fakeType: 'https://www.fakeTestUrl.org/2024/credentials/v1#fakeType'
  }
};
loader.addStatic(
  'https://www.fakeTestUrl.org/2024/credentials/v1',
  bogusContext
);
