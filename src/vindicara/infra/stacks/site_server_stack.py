"""ECS Fargate + ALB for the server-rendered vindicara.io (adapter-node).

Replaces the static S3/CloudFront export with a live Node server so the
Flightdeck console runs dynamic + real-time in the same app. Lives in the
workload region (us-west-2) because the ALB and its ACM certificate are
regional (unlike the CloudFront cert in :mod:`site_stack`, which must be
us-east-1).

The same container image is the self-hostable Flightdeck artifact: a customer
runs it in their own VPC / air-gapped network, so security headers live in the
app (vindicara-site/src/hooks.server.js), not at a CloudFront edge that a
self-hosted deployment would not have.

Deploy: VINDICARA_AWS_ACCOUNT_ID=... cdk deploy VindicaraSiteServer
(requires Docker running locally; CDK builds + pushes the image as an asset).
"""

import os

from aws_cdk import CfnOutput, Duration, Environment, Stack
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecr_assets as ecr_assets
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_ecs_patterns as ecs_patterns
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_logs as logs
from aws_cdk import aws_route53 as route53
from constructs import Construct

DOMAIN = "vindicara.io"

# vindicara-site/ relative to this file: stacks -> infra -> vindicara -> src -> repo root.
_SITE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "vindicara-site")
)


class SiteServerStack(Stack):
    """Server-rendered vindicara.io on Fargate behind an ALB (us-west-2)."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        api_origin: str = "https://qk0ymrk5be.execute-api.us-west-2.amazonaws.com",
        env: Environment | None = None,
    ) -> None:
        super().__init__(scope, construct_id, env=env)

        # Default VPC + public subnets: Fargate tasks get a public IP to pull the
        # image and reach the API, so there is no NAT gateway to pay for.
        vpc = ec2.Vpc.from_lookup(self, "DefaultVpc", is_default=True)
        zone = route53.HostedZone.from_lookup(self, "Zone", domain_name=DOMAIN)

        # Regional ACM cert for the ALB (DNS-validated against the hosted zone).
        certificate = acm.Certificate(
            self,
            "AlbCertificate",
            domain_name=DOMAIN,
            subject_alternative_names=[f"www.{DOMAIN}"],
            validation=acm.CertificateValidation.from_dns(zone),
        )

        # CDK builds vindicara-site/Dockerfile and pushes it as an asset image.
        image = ecr_assets.DockerImageAsset(self, "SiteImage", directory=_SITE_DIR)

        cluster = ecs.Cluster(self, "SiteCluster", vpc=vpc, container_insights=True)

        log_group = logs.LogGroup(
            self,
            "SiteLogs",
            retention=logs.RetentionDays.ONE_MONTH,
        )

        service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self,
            "SiteService",
            cluster=cluster,
            cpu=512,
            memory_limit_mib=1024,
            desired_count=2,
            assign_public_ip=True,
            public_load_balancer=True,
            redirect_http=True,
            certificate=certificate,
            protocol=elbv2.ApplicationProtocol.HTTPS,
            # No domain_name/domain_zone on purpose: do NOT auto-create the
            # vindicara.io A-record. The live record still points at CloudFront,
            # so the static site stays up. Verify this ALB at its own DNS first,
            # then cut vindicara.io -> ALB as a deliberate, reversible step.
            task_image_options=ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                image=ecs.ContainerImage.from_docker_image_asset(image),
                container_port=3000,
                environment={
                    "NODE_ENV": "production",
                    "PORT": "3000",
                    # SvelteKit reads PUBLIC_* at build time, but the API origin is
                    # also passed at runtime for the security-header hook's CSP.
                    "AIR_API_ORIGIN": api_origin,
                },
                log_driver=ecs.LogDrivers.aws_logs(stream_prefix="site", log_group=log_group),
            ),
            health_check_grace_period=Duration.seconds(30),
        )

        # SvelteKit's node server returns 200 on /; 200-399 covers any redirect.
        service.target_group.configure_health_check(
            path="/",
            healthy_http_codes="200-399",
            interval=Duration.seconds(30),
            timeout=Duration.seconds(5),
            healthy_threshold_count=2,
            unhealthy_threshold_count=3,
        )

        # Connection draining so in-flight requests finish on deploy/scale-in.
        service.target_group.set_attribute("deregistration_delay.timeout_seconds", "20")

        scaling = service.service.auto_scale_task_count(min_capacity=2, max_capacity=6)
        scaling.scale_on_cpu_utilization(
            "CpuScaling",
            target_utilization_percent=60,
            scale_in_cooldown=Duration.seconds(120),
            scale_out_cooldown=Duration.seconds(60),
        )

        CfnOutput(self, "AlbDnsName", value=service.load_balancer.load_balancer_dns_name)
        CfnOutput(self, "ServiceUrl", value=f"https://{DOMAIN}")
        CfnOutput(self, "EcrImageUri", value=image.image_uri)

        self.service = service
        self.certificate = certificate
