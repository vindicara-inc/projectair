"""S3 + CloudFront + ACM for vindicara.io marketing site.

This stack must deploy to us-east-1 because CloudFront requires its viewer ACM
certificate to live in us-east-1, regardless of where the rest of the workload
runs. The S3 site bucket and the CloudFront distribution are co-located in
us-east-1 for simplicity.

The dashboard is the air-dashboard SvelteKit static build, deployed to
/dashboard/ in S3 by deploy-site.sh. No API Gateway proxy needed.
"""

from aws_cdk import CfnOutput, Duration, Environment, RemovalPolicy, Stack
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cloudwatch_actions
from aws_cdk import aws_iam as iam
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as sns_subscriptions
from constructs import Construct

GITHUB_ORG = "vindicara-inc"
GITHUB_REPO = "projectair"

ALARM_EMAIL = "kev.minn9@gmail.com"


class SiteStack(Stack):
    """vindicara.io static site via CloudFront + S3."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        api_endpoint_id: str = "tbd",
        api_region: str = "us-west-2",
        env: Environment | None = None,
    ) -> None:
        super().__init__(scope, construct_id, env=env)
        self._api_endpoint_id = api_endpoint_id
        self._api_region = api_region

        site_bucket = s3.Bucket(
            self,
            "SiteBucket",
            bucket_name=f"vindicara-site-{self.account}",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            removal_policy=RemovalPolicy.RETAIN,
            versioned=False,
            enforce_ssl=True,
        )

        certificate = acm.Certificate(
            self,
            "SiteCertificate",
            domain_name="vindicara.io",
            subject_alternative_names=["www.vindicara.io"],
            validation=acm.CertificateValidation.from_dns(),
        )

        s3_origin = origins.S3BucketOrigin.with_origin_access_control(site_bucket)

        # SvelteKit static export emits `/foo/index.html` for prerendered route
        # `/foo`. Routes marked `prerender = false` (e.g. /contact, which reads
        # URL query params) emit no file; they rely on the SPA fallback at
        # /404.html, which boots the client-side router. With S3 OAC against
        # the REST endpoint, S3 does not auto-resolve either case, so this
        # function rewrites the URI on viewer-request before the origin lookup.
        url_rewrite_function = cloudfront.Function(
            self,
            "UrlRewriteFunction",
            code=cloudfront.FunctionCode.from_inline(
                "var SPA_ROUTES = ['/contact', '/contact/'];\n"
                "function handler(event) {\n"
                "  var request = event.request;\n"
                "  var uri = request.uri;\n"
                "  if (SPA_ROUTES.indexOf(uri) !== -1) {\n"
                "    request.uri = '/404.html';\n"
                "    return request;\n"
                "  }\n"
                "  if (uri.endsWith('/')) {\n"
                "    request.uri = uri + 'index.html';\n"
                "    return request;\n"
                "  }\n"
                "  if (!uri.includes('.')) {\n"
                "    return {\n"
                "      statusCode: 301,\n"
                "      statusDescription: 'Moved Permanently',\n"
                "      headers: { location: { value: uri + '/' } }\n"
                "    };\n"
                "  }\n"
                "  return request;\n"
                "}\n"
            ),
            comment="Trailing-slash redirect for directory paths; index.html rewrite for directories; SPA fallback for client-only routes.",
        )

        distribution = cloudfront.Distribution(
            self,
            "SiteDistribution",
            domain_names=["vindicara.io", "www.vindicara.io"],
            certificate=certificate,
            default_behavior=cloudfront.BehaviorOptions(
                origin=s3_origin,
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD,
                cached_methods=cloudfront.CachedMethods.CACHE_GET_HEAD,
                compress=True,
                function_associations=[
                    cloudfront.FunctionAssociation(
                        function=url_rewrite_function,
                        event_type=cloudfront.FunctionEventType.VIEWER_REQUEST,
                    )
                ],
            ),
            default_root_object="index.html",
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
            http_version=cloudfront.HttpVersion.HTTP2_AND_3,
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
            comment="vindicara.io static site + /dashboard* proxy",
        )

        CfnOutput(
            self,
            "SiteBucketName",
            value=site_bucket.bucket_name,
            description="S3 bucket holding the SvelteKit build output.",
        )
        CfnOutput(
            self,
            "DistributionId",
            value=distribution.distribution_id,
            description="CloudFront distribution ID; use for invalidations.",
        )
        CfnOutput(
            self,
            "DistributionDomain",
            value=distribution.distribution_domain_name,
            description="CloudFront default domain (xxxxx.cloudfront.net).",
        )
        CfnOutput(
            self,
            "CertificateArn",
            value=certificate.certificate_arn,
            description="ACM certificate ARN. Stack stalls on creation until DNS validation completes.",
        )

        alarm_topic = sns.Topic(
            self,
            "SiteAlarmTopic",
            topic_name="vindicara-site-alarms",
            display_name="Vindicara site alarms",
        )
        alarm_topic.add_subscription(sns_subscriptions.EmailSubscription(ALARM_EMAIL))

        cf_5xx_alarm = cloudwatch.Alarm(
            self,
            "CloudFront5xxAlarm",
            alarm_name="vindicara-cloudfront-5xx-rate",
            alarm_description="CloudFront 5xx error rate >= 1% sustained 2 of 3 5-min datapoints.",
            metric=cloudwatch.Metric(
                namespace="AWS/CloudFront",
                metric_name="5xxErrorRate",
                dimensions_map={
                    "DistributionId": distribution.distribution_id,
                    "Region": "Global",
                },
                statistic="Average",
                period=Duration.minutes(5),
            ),
            threshold=1.0,
            evaluation_periods=3,
            datapoints_to_alarm=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        cf_5xx_alarm.add_alarm_action(cloudwatch_actions.SnsAction(alarm_topic))

        oidc_provider = iam.OpenIdConnectProvider(
            self,
            "GitHubOIDC",
            url="https://token.actions.githubusercontent.com",
            client_ids=["sts.amazonaws.com"],
        )

        deploy_role = iam.Role(
            self,
            "GitHubDeployRole",
            role_name="vindicara-github-deploy",
            assumed_by=iam.WebIdentityPrincipal(
                oidc_provider.open_id_connect_provider_arn,
                conditions={
                    "StringEquals": {
                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    },
                    "StringLike": {
                        "token.actions.githubusercontent.com:sub": f"repo:{GITHUB_ORG}/{GITHUB_REPO}:*",
                    },
                },
            ),
            max_session_duration=Duration.hours(1),
        )

        site_bucket.grant_read_write(deploy_role)
        site_bucket.grant_delete(deploy_role)
        deploy_role.add_to_policy(
            iam.PolicyStatement(
                actions=["cloudfront:CreateInvalidation"],
                resources=[f"arn:aws:cloudfront::{self.account}:distribution/{distribution.distribution_id}"],
            )
        )

        CfnOutput(
            self,
            "DeployRoleArn",
            value=deploy_role.role_arn,
            description="GitHub Actions OIDC deploy role ARN. Set as AWS_DEPLOY_ROLE_ARN in GitHub environment vars.",
        )

        self.site_bucket = site_bucket
        self.distribution = distribution
        self.certificate = certificate
