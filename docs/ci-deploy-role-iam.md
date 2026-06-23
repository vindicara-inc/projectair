# CI deploy role IAM (vindicara.io SSR / `cdk deploy`)

The `deploy-site.yml` workflow assumes the GitHub OIDC role in
`${{ vars.AWS_DEPLOY_ROLE_ARN }}` and runs `cdk deploy VindicaraSiteServer`.
The old static workflow only needed S3 + CloudFront permissions; `cdk deploy`
instead needs to **assume the CDK bootstrap roles**. Modern CDK v2 does all the
privileged work (CloudFormation, ECR push, S3 asset upload, context lookups)
through those bootstrap roles, so the CI role itself stays minimal.

- Account: `399827112476`
- Workload region (this stack): `us-west-2`
- Site cert stack region (lookups only): `us-east-1`
- CDK bootstrap qualifier: `hnb659fds` (default; confirmed by the asset repo
  name `cdk-hnb659fds-container-assets-399827112476-us-west-2`)

## 1. Permissions policy (attach to the deploy role)

This is the new part. It lets the CI role assume the four CDK bootstrap roles
and read the bootstrap version parameter.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeCdkBootstrapRoles",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::399827112476:role/cdk-hnb659fds-*"
    },
    {
      "Sid": "ReadCdkBootstrapVersion",
      "Effect": "Allow",
      "Action": "ssm:GetParameter",
      "Resource": "arn:aws:ssm:*:399827112476:parameter/cdk-bootstrap/hnb659fds/version"
    }
  ]
}
```

The `cdk-hnb659fds-*` wildcard covers the deploy, file-publishing,
image-publishing, and lookup roles in every region (us-west-2 for the deploy,
us-east-1 for the cross-region lookups during synth of the full app). It only
matches CDK's own bootstrap roles, so it is safe. For strict least privilege,
replace the wildcard with the explicit list:

```
arn:aws:iam::399827112476:role/cdk-hnb659fds-deploy-role-399827112476-us-west-2
arn:aws:iam::399827112476:role/cdk-hnb659fds-file-publishing-role-399827112476-us-west-2
arn:aws:iam::399827112476:role/cdk-hnb659fds-image-publishing-role-399827112476-us-west-2
arn:aws:iam::399827112476:role/cdk-hnb659fds-lookup-role-399827112476-us-west-2
arn:aws:iam::399827112476:role/cdk-hnb659fds-lookup-role-399827112476-us-east-1
```

(`cdk.context.json` is committed, so cached lookups usually mean the lookup
roles are not exercised at synth time; they are listed for safety.)

## 2. Trust policy (verify it allows this workflow)

The role already trusts GitHub OIDC (the old workflow used it). Confirm the
trust statement matches the repo and the `production` environment the workflow
runs in:

```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::399827112476:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
    },
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:vindicara-inc/projectair:environment:production"
    }
  }
}
```

Notes:
- Replace `vindicara-inc/projectair` with the actual repo slug if it differs.
- The `:environment:production` sub matches because the job declares
  `environment: production`. To allow any ref instead, use
  `repo:vindicara-inc/projectair:*`.

## 3. One-time prerequisite: bootstrap must exist

The account/region is already bootstrapped (the bootstrap roles and the asset
ECR repo exist, since the stack deployed). If you ever recreate the account,
run once: `cdk bootstrap aws://399827112476/us-west-2 aws://399827112476/us-east-1`.

## 4. If the bootstrap roles do not trust the account root

Default `cdk bootstrap` makes the bootstrap roles assumable by
`arn:aws:iam::399827112476:root`, so any in-account principal with the
`sts:AssumeRole` permission above can assume them. If your bootstrap was created
with `--trust <accounts>` or a custom trust, add the deploy role's ARN to the
bootstrap roles' trust (or re-run `cdk bootstrap` with `--trust 399827112476`).

## Verifying

After attaching the policy, trigger the workflow manually (Actions ->
Deploy site -> Run workflow) before relying on it for a real push. A successful
run ends with `cdk deploy` printing `VindicaraSiteServer` outputs. If it fails
on `AccessDenied` assuming a `cdk-hnb659fds-*` role, that points back to section
1 (policy) or section 4 (bootstrap trust).
