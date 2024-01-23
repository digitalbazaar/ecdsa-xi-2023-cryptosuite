/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import jsonld from 'jsonld';

export async function canonize(input, options) {
  return jsonld.canonize(input, {
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    ...options
  });
}
