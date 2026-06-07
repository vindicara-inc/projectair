// Auth routes (callback + logout) must be served at the trailing-slash URL.
// The static host (S3/CloudFront) canonicalizes to the slash form and drops the
// query string on the redirect; landing directly on the slash URL keeps ?code=
// intact so the callback can complete the Auth0 exchange.
export const trailingSlash = 'always';
