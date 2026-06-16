// Contact-form backend for vindicara.io.
// AWS Lambda (Node 20) exposed via a Function URL. Sends submissions to support@vindicara.io
// through SES v2. No third-party form processor: prospect data stays in your AWS account.
//
// Setup steps are in ../../CONTACT_FORM.md.

import { SESv2Client, SendEmailCommand } from '@aws-sdk/client-sesv2';

const ses = new SESv2Client({});

const TO = 'support@vindicara.io';
const FROM = 'support@vindicara.io';          // must be an SES-verified identity
const ALLOW_ORIGIN = 'https://vindicara.io';  // lock CORS to the site origin

const cors = {
  'access-control-allow-origin': ALLOW_ORIGIN,
  'access-control-allow-methods': 'POST, OPTIONS',
  'access-control-allow-headers': 'content-type'
};

/** @param {any} event */
export const handler = async (event) => {
  const method = event?.requestContext?.http?.method;
  if (method === 'OPTIONS') return { statusCode: 204, headers: cors };
  if (method !== 'POST') return { statusCode: 405, headers: cors, body: 'Method Not Allowed' };

  let data;
  try {
    data = JSON.parse(event.body || '{}');
  } catch {
    return { statusCode: 400, headers: cors, body: 'Invalid JSON' };
  }

  // Honeypot: real users never fill a hidden field. Silently accept and drop bots.
  if (data.website) return { statusCode: 200, headers: cors, body: JSON.stringify({ ok: true }) };

  const name = String(data.name || '').slice(0, 200).trim();
  const email = String(data.email || '').slice(0, 200).trim();
  if (!name || !email.includes('@')) {
    return { statusCode: 422, headers: cors, body: 'Name and a valid email are required.' };
  }

  const company = String(data.company || '').slice(0, 200);
  const team = String(data.team || '').slice(0, 100);
  const prove = String(data.prove || '').slice(0, 5000);
  const designPartner = data.designPartner ? 'yes' : 'no';

  const text = [
    `Name: ${name}`,
    `Email: ${email}`,
    `Company: ${company}`,
    `Team: ${team}`,
    `Design partner: ${designPartner}`,
    '',
    prove
  ].join('\n');

  try {
    await ses.send(new SendEmailCommand({
      FromEmailAddress: FROM,
      Destination: { ToAddresses: [TO] },
      ReplyToAddresses: [email],
      Content: {
        Simple: {
          Subject: { Data: `Project AIR inquiry from ${name}` },
          Body: { Text: { Data: text } }
        }
      }
    }));
    return {
      statusCode: 200,
      headers: { ...cors, 'content-type': 'application/json' },
      body: JSON.stringify({ ok: true })
    };
  } catch (err) {
    console.error('SES send failed', err);
    return { statusCode: 502, headers: cors, body: 'Email send failed' };
  }
};
