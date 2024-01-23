/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';

export async function createVerifier({verificationMethod}) {
  const key = await EcdsaMultikey.from(verificationMethod);
  const verifier = key.verifier();
  return verifier;
}
