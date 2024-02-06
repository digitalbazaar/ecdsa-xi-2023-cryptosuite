/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
export function concat(b1, b2, b3) {
  const rval = new Uint8Array(b1.length + b2.length + b3.length);
  rval.set(b1, 0);
  rval.set(b2, b1.length);
  rval.set(b3, b1.length + b2.length);
  return rval;
}
