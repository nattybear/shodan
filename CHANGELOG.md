# Changelog

This package follows the [Haskell Package Versioning Policy](https://pvp.haskell.org/).

## 0.4.0.0 — 2026-11-21

### Breaking changes

- Add `InvalidDomain` to `ShodanError`; exhaustive handlers need a new case.
- Append timestamp, hostname, domain, ALPN, and certificate DNS name fields to the public `SearchMatch`
  constructor. Positional construction and patterns need five additional fields;
  this datatype change requires a PVP major bump.

### Additions

- Add `getDomainInfo`, `DomainInfo`, and `DnsRecord` for a single page of domain
  DNS information, with explicit page selection and validation before HTTP.
- Add `shodan-domain DOMAIN [PAGE]`, including subdomains, records, last-seen
  timestamps, and the next-page flag. Each lookup uses one query credit;
  history and record-type filters are not implemented yet.
- Add domain parsing, HTTP, and argument validation tests and documentation.
  Verify a live domain lookup manually; use `domainMore` rather than assuming
  a fixed number of records per page.
- Add `matchTimestamp` (UTC collection time preserved as text), `matchHostnames`,
  `matchDomains`, and nested `ssl.alpn` as `matchAlpn`.
- Missing or null metadata becomes `Nothing`; empty lists remain `Just []`.
  Incorrect JSON types are rejected. Timestamp syntax is not validated.
- Show collection time, hostnames, domains, and ALPN in the search executable.
- Add `matchCertificateNames` and a `CERTIFICATE_NAMES` column for DNS names
  from the leaf certificate SAN, including wildcards. Decode DER and escaped
  byte representations; omit non-DNS entries and reject malformed SAN data.
  Certificate names are candidates, not verified DNS mappings or live sites.
- Add local parsing tests and document the meaning and limits of the metadata.
- Verify search metadata manually; automated tests remain local.

## 0.3.0.0 — 2026-11-20

### Breaking changes

- Added `matchVersion :: Maybe Text` to `SearchMatch`, changing its constructor
  arity. Update positional constructor calls and patterns for the new field
  between product and ASN. This datatype change requires a PVP major bump.

### Additions

- Parse the optional Shodan `version` string; missing or null values become
  `Nothing`, and non-text values are rejected.
- Display a `VERSION` column in `shodan-search`, using `-` when unavailable.
- Test present, absent, null, and invalid version values.

## 0.2.0.0 — 2026-11-20

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
