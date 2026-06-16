# Contact form: wiring it to email

The form in `src/routes/contact/+page.svelte` POSTs JSON to `CONTACT_ENDPOINT`. Until you set
that constant, it falls back to a prefilled `mailto:support@vindicara.io`, so it is never a dead
end. To get real in-page submissions, deploy the Lambda in `infra/contact-lambda/` and paste its
Function URL into `CONTACT_ENDPOINT`.

## One-time AWS setup (us-west-2, account 399827112476)

1. **Verify the SES sender.** In SES, verify `support@vindicara.io` (or the `vindicara.io`
   domain, which also helps deliverability). If your SES account is still in the sandbox, either
   request production access or verify `support@vindicara.io` as a recipient too.

2. **Create the Lambda.** Runtime Node 20. Upload `infra/contact-lambda/index.mjs` (zip the
   folder, or paste into the console as `index.mjs`). The AWS SDK v3 is provided by the runtime,
   no `npm install` needed.

3. **Grant SES send.** Attach an inline policy to the Lambda role:

   ```json
   { "Version": "2012-10-17", "Statement": [
     { "Effect": "Allow", "Action": ["ses:SendEmail"], "Resource": "*" }
   ]}
   ```

4. **Enable a Function URL.** Auth type `NONE` (the handler enforces method + CORS). Set CORS
   allow-origin to `https://vindicara.io`. Copy the URL.

5. **Point the site at it.** Set `const CONTACT_ENDPOINT = 'https://<id>.lambda-url.us-west-2.on.aws/';`
   in `src/routes/contact/+page.svelte`, then `npm run build` and deploy.

## Test

- Submit the live form: you get an in-page "Thank you," and the message arrives at
  support@vindicara.io with the sender's address in Reply-To.
- Submit with the hidden `website` field populated (via devtools): the request returns 200 but no
  email is sent (honeypot working).

## Notes

- The Function URL is public and unauthenticated. The honeypot stops basic bots; if you see spam,
  add AWS WAF rate limiting on the Function URL or a CAPTCHA.
- The handler caps field lengths and sets Reply-To to the submitter so you can reply directly.
