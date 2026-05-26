"""DynamoDB tables and S3 buckets for Vindicara."""

from aws_cdk import Duration, RemovalPolicy, Stack
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_s3 as s3
from constructs import Construct


class DataStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs: object) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.policies_table = dynamodb.Table(
            self,
            "PoliciesTable",
            table_name="vindicara-policies",
            partition_key=dynamodb.Attribute(name="pk", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="sk", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.RETAIN,
            point_in_time_recovery=True,
        )

        self.evaluations_table = dynamodb.Table(
            self,
            "EvaluationsTable",
            table_name="vindicara-evaluations",
            partition_key=dynamodb.Attribute(name="pk", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="sk", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.RETAIN,
            time_to_live_attribute="ttl",
        )

        self.api_keys_table = dynamodb.Table(
            self,
            "APIKeysTable",
            table_name="vindicara-api-keys",
            partition_key=dynamodb.Attribute(name="pk", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.RETAIN,
        )

        self.audit_bucket = s3.Bucket(
            self,
            "AuditBucket",
            bucket_name=f"vindicara-audit-{self.account}",
            versioned=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="archive-after-90-days",
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                            transition_after=Duration.days(90),
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(365),
                        ),
                    ],
                ),
            ],
        )

        self.identity_registrations_table = dynamodb.Table(
            self,
            "IdentityRegistrationsTable",
            table_name="vindicara-identity-registrations",
            partition_key=dynamodb.Attribute(name="email", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="registered_at", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.RETAIN,
        )

        self.telemetry_pings_table = dynamodb.Table(
            self,
            "TelemetryPingsTable",
            table_name="vindicara-telemetry-pings",
            partition_key=dynamodb.Attribute(name="session_id", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="timestamp", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            time_to_live_attribute="ttl",
        )
