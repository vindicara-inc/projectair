// /contact reads URL query params (?tier=team) and runs an interactive form.
// Static prerender cannot supply a URL, so render this route on the client
// only. This keeps the rest of the static-adapter site fully prerendered.
export const prerender = false;
export const ssr = false;
