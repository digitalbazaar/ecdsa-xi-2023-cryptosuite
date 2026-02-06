# @digitalbazaar/ecdsa-xi-2023-cryptosuite Changelog

## 1.2.0 - 2026-02-05

### Changed
- Update dependencies:
  - `@digitalbazaar/di-sd-primitives@3.2.0`.
  - `jsonld@9`.
  - `jsonld-signatures@11.6.0`.
  - `rdf-canonize@5`.
- **NOTE**: The `jsonld` updates may have rare edge case compatibility issues.
  The important related `rdf-canonize` issues were addressed in v1.1.0.

## 1.1.0 - 2024-11-25

### Added
- Add support for `@direction`.

### Changed
- Update C14N alg to RDFC-1.0.

## 1.0.1 - 2024-02-15

### Fixed
- Pass documentLoader to canonize.

## 1.0.0 - 2024-02-06

### Added
- Initial version.
