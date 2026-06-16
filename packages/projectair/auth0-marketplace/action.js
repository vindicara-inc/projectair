/**
 * Project AIR - Auth0 Login Action
 *
 * Records authenticated human approvals in the AIR forensic chain.
 * When an AI agent requires human authorization for a sensitive action,
 * this Action sends the verified identity to AIR Cloud so the approval
 * is cryptographically signed and tamper-evident.
 *
 * Secrets required:
 *   AIR_API_KEY    - Your Project AIR API key
 *   AIR_CLOUD_URL  - AIR Cloud endpoint (default: https://cloud.vindicara.io)
 *   AUTH0_DOMAIN   - Your Auth0 tenant domain
 */
exports.onExecutePostLogin = async (event, api) => {
  const AIR_CLOUD_URL = event.secrets.AIR_CLOUD_URL || 'https://cloud.vindicara.io';
  const AIR_API_KEY = event.secrets.AIR_API_KEY;

  if (!AIR_API_KEY) return;

  await fetch(`${AIR_CLOUD_URL}/v1/capsules`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': AIR_API_KEY,
    },
    body: JSON.stringify({
      kind: 'human_approval',
      payload: {
        human_approval: {
          decision: 'approve',
          approver_sub: event.user.user_id,
          approver_email: event.user.email,
          issuer: `https://${event.secrets.AUTH0_DOMAIN}/`,
          audience: event.client.client_id,
          issued_at: Math.floor(Date.now() / 1000),
          expires_at: Math.floor(Date.now() / 1000) + 3600,
        },
      },
    }),
  });
};
