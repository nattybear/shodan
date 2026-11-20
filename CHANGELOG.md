# Changelog

This package follows the [Haskell Package Versioning Policy](https://pvp.haskell.org/).

## 0.2.0.0 — Unreleased

### Breaking changes

- Added `InvalidPage` to the public `ShodanError` type. Consumers that explicitly
  handle every constructor should add a case for this error. This datatype
  change requires a major version increase under PVP.

### Additions

- Added `searchHosts` for one page of `GET /shodan/host/search`, with an explicit
  page number starting at 1. Invalid page numbers are rejected before HTTP;
  additional pages are not fetched automatically.
- Added `SearchMatch` with IP, port, optional product, and optional ASN fields.
- Added `SearchResult` with total results, the current page of service matches,
  and optional facet breakdowns.
- Added the `shodan-search` executable, with an optional page argument and
  tabular service output. It reads `SHODAN_API_KEY` from the environment.
- Added search JSON parsing and local HTTP tests for page selection, query
  encoding, invalid pages, error responses, and malformed responses.
- Updated the README and Haddock documentation with search usage and credit
  behavior. Live search was also verified manually; automated tests remain local.

## 0.1.0.0 — 2026-11-20

- Initial Hackage release under the BSD 3-Clause License.
- Added API plan information and search result count requests.
- Added `ApiInfo`, `UsageLimits`, `CountResult`, and `Facet` response types.
- Added TLS client construction, redacted client display, HTTP error handling,
  and a finite response timeout without automatic redirect following.
- Added the `shodan-api-info` and `shodan-count` executable examples, local
  response parsing and HTTP tests, and Haddock documentation.
