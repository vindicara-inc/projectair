"""Vindicara ops chain infrastructure.

Provisions:

- ``vindicara-ops-chain`` DynamoDB table (chain_id partition + ord sort)
- ``vindicara-ops-chain-public-{account}`` S3 bucket (read-public on the
  ``ops-chain/*`` prefix, blocks public ACLs everywhere else)
- Two cron Lambdas: anchorer (60s cadence) and publisher (60s cadence)
- IAM grants so the Lambdas can scan/write DDB and write S3
- An ``ops_chain_table`` exposed for the API stack to grant write access

The CDK app wires the api stack against ``ops_chain_table`` so prod
Lambda invocations can emit AgDR records into the chain.
"""

from aws_cdk import Duration, RemovalPolicy, Stack
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cloudwatch_actions
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as events_targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as sns_subscriptions
from constructs import Construct

# Cron cadence for both anchorer and publisher Lambdas. EventBridge rate
# minimum is 1 minute, so the design's "30-60s cadence" floor is 60s.
ANCHORER_TIMEOUT_SECONDS = 120
PUBLISHER_TIMEOUT_SECONDS = 60
ALARM_EMAIL = "alerts@vindicara.io"


class OpsChainStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs: object) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.ops_chain_table = dynamodb.Table(
            self,
            "OpsChainTable",
            table_name="vindicara-ops-chain",
            partition_key=dynamodb.Attribute(name="chain_id", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="ord", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.RETAIN,
            point_in_time_recovery=True,
        )

        self.ops_chain_bucket = s3.Bucket(
            self,
            "OpsChainBucket",
            bucket_name=f"vindicara-ops-chain-public-{self.account}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            removal_policy=RemovalPolicy.RETAIN,
            block_public_access=s3.BlockPublicAccess(
                block_public_acls=True,
                ignore_public_acls=True,
                block_public_policy=False,
                restrict_public_buckets=False,
            ),
            cors=[
                s3.CorsRule(
                    allowed_methods=[s3.HttpMethods.GET, s3.HttpMethods.HEAD],
                    allowed_origins=["*"],
                    allowed_headers=["*"],
                    max_age=3600,
                ),
            ],
        )
        self.ops_chain_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[iam.AnyPrincipal()],
                actions=["s3:GetObject"],
                resources=[self.ops_chain_bucket.arn_for_objects("ops-chain/*")],
            ),
        )

        # The anchoring identity is an ECDSA P-256 PEM stored in Secrets
        # Manager. Operators populate the secret out-of-band (see
        # docs/ops-chain-deploy.md) before the anchorer's first run; the
        # secret resource itself is declarative here so the IAM grant and
        # env wiring are not a manual step.
        self.anchoring_key_secret = secretsmanager.Secret(
            self,
            "AnchoringKeySecret",
            secret_name="vindicara/ops-chain/anchoring-key",  # noqa: S106 - secret resource name, not a value
            description="ECDSA P-256 PEM signing the Vindicara ops chain anchors to public Sigstore Rekor. Operator-populated.",
            removal_policy=RemovalPolicy.RETAIN,
        )

        common_env = {
            "VINDICARA_OPS_CHAIN_TABLE": self.ops_chain_table.table_name,
            "VINDICARA_OPS_CHAIN_BUCKET": self.ops_chain_bucket.bucket_name,
            "VINDICARA_ANCHORING_KEY_SECRET_ARN": self.anchoring_key_secret.secret_arn,
        }

        self.anchorer_function = lambda_.Function(
            self,
            "AnchorerFunction",
            function_name="vindicara-ops-anchorer",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="vindicara.ops.anchorer.lambda_handler",
            code=lambda_.Code.from_asset("lambda_package"),
            memory_size=512,
            timeout=Duration.seconds(ANCHORER_TIMEOUT_SECONDS),
            environment=common_env,
            log_retention=logs.RetentionDays.ONE_YEAR,
            tracing=lambda_.Tracing.ACTIVE,
        )
        self.ops_chain_table.grant_read_write_data(self.anchorer_function)
        self.anchoring_key_secret.grant_read(self.anchorer_function)

        self.publisher_function = lambda_.Function(
            self,
            "PublisherFunction",
            function_name="vindicara-ops-publisher",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="vindicara.ops.publisher.lambda_handler",
            code=lambda_.Code.from_asset("lambda_package"),
            memory_size=256,
            timeout=Duration.seconds(PUBLISHER_TIMEOUT_SECONDS),
            environment=common_env,
            log_retention=logs.RetentionDays.ONE_YEAR,
            tracing=lambda_.Tracing.ACTIVE,
        )
        self.ops_chain_table.grant_read_write_data(self.publisher_function)
        self.ops_chain_bucket.grant_put(self.publisher_function)

        events.Rule(
            self,
            "AnchorerSchedule",
            rule_name="vindicara-ops-anchorer-schedule",
            schedule=events.Schedule.rate(Duration.minutes(1)),
            targets=[events_targets.LambdaFunction(self.anchorer_function)],
        )

        events.Rule(
            self,
            "PublisherSchedule",
            rule_name="vindicara-ops-publisher-schedule",
            schedule=events.Schedule.rate(Duration.minutes(1)),
            targets=[events_targets.LambdaFunction(self.publisher_function)],
        )

        alarm_topic = sns.Topic(
            self,
            "OpsChainAlarmTopic",
            topic_name="vindicara-ops-chain-alarms",
            display_name="Vindicara ops chain alarms",
        )
        alarm_topic.add_subscription(sns_subscriptions.EmailSubscription(ALARM_EMAIL))

        anchorer_errors_alarm = cloudwatch.Alarm(
            self,
            "AnchorerErrorsAlarm",
            alarm_name="vindicara-ops-anchorer-errors",
            alarm_description="Anchorer Lambda errors >= 3 across 5 minutes (3 cron ticks).",
            metric=self.anchorer_function.metric_errors(period=Duration.minutes(5)),
            threshold=3,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        anchorer_errors_alarm.add_alarm_action(cloudwatch_actions.SnsAction(alarm_topic))

        publisher_errors_alarm = cloudwatch.Alarm(
            self,
            "PublisherErrorsAlarm",
            alarm_name="vindicara-ops-publisher-errors",
            alarm_description="Publisher Lambda errors >= 3 across 5 minutes.",
            metric=self.publisher_function.metric_errors(period=Duration.minutes(5)),
            threshold=3,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        publisher_errors_alarm.add_alarm_action(cloudwatch_actions.SnsAction(alarm_topic))

        anchorer_no_invocations_alarm = cloudwatch.Alarm(
            self,
            "AnchorerNoInvocationsAlarm",
            alarm_name="vindicara-ops-anchorer-not-running",
            alarm_description="Anchorer Lambda has not been invoked in the last 5 minutes (cron schedule may be disabled).",
            metric=self.anchorer_function.metric_invocations(period=Duration.minutes(5)),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.BREACHING,
        )
        anchorer_no_invocations_alarm.add_alarm_action(cloudwatch_actions.SnsAction(alarm_topic))
