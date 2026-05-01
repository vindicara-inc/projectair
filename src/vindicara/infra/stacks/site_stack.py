"""S3 + CloudFront + ACM for vindicara.io marketing site and dashboard proxy.

This stack must deploy to us-east-1 because CloudFront requires its viewer ACM
certificate to live in us-east-1, regardless of where the rest of the workload
runs. The S3 site bucket and the CloudFront distribution are co-located in
us-east-1 for simplicity. The dashboard origin is the API Gateway in the
workload region (us-west-2); CloudFront makes the cross-region hop transparent.
"""

from aws_cdk import CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cloudwatch_actions
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as sns_subscriptions
from constructs import Construct

ALARM_EMAIL = "kev.minn9@gmail.com"


class SiteStack(Stack):
    """vindicara.io static site + /dashboard* proxy via CloudFront."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        api_endpoint_id: str,
        api_region: str,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

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

        api_origin_domain = f"{api_endpoint_id}.execute-api.{api_region}.amazonaws.com"

        s3_origin = origins.S3BucketOrigin.with_origin_access_control(site_bucket)
        api_origin = origins.HttpOrigin(
            api_origin_domain,
            protocol_policy=cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
        )

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
                "  } else if (!uri.includes('.')) {\n"
                "    request.uri = uri + '/index.html';\n"
                "  }\n"
                "  return request;\n"
                "}\n"
            ),
            comment="Rewrite extension-less paths to /index.html. Route SPA-only paths to /404.html (SvelteKit fallback shell).",
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
            additional_behaviors={
                "/dashboard*": cloudfront.BehaviorOptions(
                    origin=api_origin,
                    viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                    allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                    cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                    origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
                ),
            },
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

        self.site_bucket = site_bucket
        self.distribution = distribution
        self.certificate = certificate
