/**
 * IP → country / ASN lookups for Bloodwork's sender map.
 *
 * PHASE 2. Reads MaxMind GeoLite2 (Country + ASN) mmdb files stored in R2 and
 * served by `/api/geo`. GeoLite2 is free but requires a MaxMind account, a
 * license key and visible attribution — none of which exist yet, so nothing
 * here ships until they do.
 *
 * Planned surface:
 *   createGeoReader(buffer)     mmdb-lib reader over an R2 object
 *   lookupCountry(ip)           ISO code + name
 *   lookupAsn(ip)               ASN + organisation
 */
export const GEO_PHASE = 2 as const;

/** Required wherever GeoLite2 data is displayed. */
export const MAXMIND_ATTRIBUTION =
  'IP geolocation by MaxMind GeoLite2 — https://www.maxmind.com';
