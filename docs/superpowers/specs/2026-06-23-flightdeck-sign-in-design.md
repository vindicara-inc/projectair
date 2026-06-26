# Flightdeck sign-in page

## Goal

Replace Flightdeck's current in-dashboard lock prompt with a dedicated sign-in route that faithfully implements the supplied Project AIR onboarding design in Svelte.

## Scope

- Add a sign-in route outside the Flightdeck dashboard shell so unauthenticated operators do not see dashboard navigation or data.
- Translate the supplied two-column desktop design into accessible, responsive Svelte markup and component-scoped CSS. On screens below the design breakpoint, retain the sign-in column and omit the supporting trust column.
- Preserve the supplied copy and visual hierarchy, including the dark navy left panel, red AIR accent, code-style Project AIR lockup, provider buttons, trust cards, and mobile behavior.

## Authentication behavior

- Google button: begin the existing Auth0 Authorization Code plus PKCE flow with the `google-oauth2` connection.
- GitHub button: begin the same Auth0 flow with the `github` connection.
- Email and SSO controls: begin the existing Auth0 flow without a forced connection so Auth0 Universal Login selects the enabled passwordless, database, or enterprise provider.
- Do not add provider client secrets, token exchange logic, or OAuth credentials to browser code. Auth0 remains the sole broker.
- Auth0 failures display actionable text on the page. A provider button is disabled while a redirect is starting.
- The demo-chain action is a visual control only until a real public demo destination is specified. It will not claim to authenticate or inspect a user machine.

## Route and session flow

1. An unauthenticated visit to Flightdeck redirects to the sign-in route.
2. A sign-in selection creates the existing PKCE verifier and redirects to Auth0.
3. The existing callback exchanges the authorization code and stores the access token.
4. The callback returns the operator to Flightdeck.
5. The existing lock action routes back to sign-in instead of rendering a second credentials surface inside the dashboard.

## Security and accessibility

- Use only exact Auth0 connection names already configured in the tenant.
- Preserve strict redirect URI validation through the current Auth0 application configuration.
- Do not expose OAuth client secrets, tokens, or identity profile contents in the page.
- Use semantic buttons and links, visible keyboard focus, button labels, and reduced-motion handling.
- The returned Auth0 `sub` claim remains the durable identity key. Email is optional profile data, not an authorization key.

## Verification

- Automated tests cover redirect selection for Google, GitHub, and generic Auth0 sign-in plus the unauthenticated route guard.
- `npm run check` and `npm run build` pass in `site/`.
- A browser pass confirms desktop and mobile layout, keyboard operation, Auth0 redirect construction, and callback return flow.

## Exclusions

- The requested new Flightdeck dashboard design is a follow-on task after the sign-in page is complete.
- Entra, Okta, Ping, and any other enterprise IdP configuration are not created in this change. The generic Auth0 entry point supports them once configured in Auth0.
