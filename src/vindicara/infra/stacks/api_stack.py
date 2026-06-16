"""Lambda function and API Gateway for Vindicara API."""

from aws_cdk import Duration, Environment, Stack
from aws_cdk import aws_apigatewayv2 as apigw
from aws_cdk import aws_apigatewayv2_integrations as integrations
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cloudwatch_actions
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_events as events
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as sns_subscriptions
from constructs import Construct

ALARM_EMAIL = "kev.minn9@gmail.com"


class APIStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        policies_table: dynamodb.Table,
        evaluations_table: dynamodb.Table,
        api_keys_table: dynamodb.Table,
        identity_registrations_table: dynamodb.Table,
        audit_bucket: s3.Bucket,
        event_bus: events.EventBus,
        env: Environment | None = None,
    ) -> None:
        super().__init__(scope, construct_id, env=env)

        self.api_function = lambda_.Function(
            self,
            "APIFunction",
            function_name="vindicara-api",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="vindicara.lambda_handler.handler",
            code=lambda_.Code.from_asset("lambda_package"),
            memory_size=256,
            timeout=Duration.seconds(30),
            environment={
                "VINDICARA_STAGE": "prod",
                "VINDICARA_LOG_LEVEL": "INFO",
                "POLICIES_TABLE": policies_table.table_name,
                "EVALUATIONS_TABLE": evaluations_table.table_name,
                "API_KEYS_TABLE": api_keys_table.table_name,
                "AUDIT_BUCKET": audit_bucket.bucket_name,
                "EVENT_BUS_NAME": event_bus.event_bus_name,
            },
            log_retention=logs.RetentionDays.ONE_MONTH,
            tracing=lambda_.Tracing.ACTIVE,
        )

        policies_table.grant_read_write_data(self.api_function)
        evaluations_table.grant_read_write_data(self.api_function)
        api_keys_table.grant_read_data(self.api_function)
        identity_registrations_table.grant_read_write_data(self.api_function)
        audit_bucket.grant_write(self.api_function)
        event_bus.grant_put_events_to(self.api_function)

        self.api_function.add_environment(
            "VINDICARA_IDENTITY_TABLE",
            identity_registrations_table.table_name,
        )

        # FlightDeck console Auth0 verification. Without these, require_operator
        # runs open (no token enforcement). Public tenant + API identifier.
        self.api_function.add_environment("AIR_AUTH0_DOMAIN", "dev-kilt2vkudvbu75ny.us.auth0.com")
        self.api_function.add_environment("AIR_AUTH0_AUDIENCE", "cabinet-coach.v2")

        # ------------------------------------------------------------------
        # Stripe fulfillment secrets (operator-supplied, not CDK-managed).
        #
        # Create this secret out-of-band before the first deploy:
        #   Name:  vindicara/fulfillment
        #   Type:  Other type of secret / Plaintext JSON
        #   Value: {"stripe_secret_key": "sk_live_...",
        #           "stripe_webhook_secret": "whsec_...",
        #           "license_signing_key_pem": "-----BEGIN PRIVATE KEY-----...",
        #           "resend_api_key": "re_...",
        #           "pro_wheel_signed_url": "https://..."}
        # ------------------------------------------------------------------
        fulfillment_secret = secretsmanager.Secret.from_secret_name_v2(self, "FulfillmentSecret", "Vindicara_dashboard")
        fulfillment_secret.grant_read(self.api_function)

        fulfillment_fields: list[tuple[str, str]] = [
            ("VINDICARA_STRIPE_SECRET_KEY", "stripe_secret_key"),
            ("VINDICARA_STRIPE_WEBHOOK_SECRET", "stripe_webhook_secret"),
            ("VINDICARA_LICENSE_SIGNING_KEY_PEM", "license_signing_key_pem"),
            ("VINDICARA_RESEND_API_KEY", "resend_api_key"),
            ("VINDICARA_PRO_WHEEL_SIGNED_URL", "pro_wheel_signed_url"),
        ]
        for env_name, json_field in fulfillment_fields:
            self.api_function.add_environment(
                env_name,
                fulfillment_secret.secret_value_from_json(json_field).unsafe_unwrap(),
            )

        self.http_api = apigw.HttpApi(
            self,
            "VindicaraAPI",
            api_name="vindicara-api",
            default_integration=integrations.HttpLambdaIntegration(
                "LambdaIntegration",
                handler=self.api_function,
            ),
            cors_preflight=apigw.CorsPreflightOptions(
                allow_headers=["*"],
                allow_methods=[
                    apigw.CorsHttpMethod.GET,
                    apigw.CorsHttpMethod.POST,
                    apigw.CorsHttpMethod.OPTIONS,
                ],
                allow_origins=["*"],
            ),
        )

        alarm_topic = sns.Topic(
            self,
            "AlarmTopic",
            topic_name="vindicara-alarms",
            display_name="Vindicara workload alarms",
        )
        alarm_topic.add_subscription(sns_subscriptions.EmailSubscription(ALARM_EMAIL))

        lambda_errors_alarm = cloudwatch.Alarm(
            self,
            "LambdaErrorsAlarm",
            alarm_name="vindicara-api-lambda-errors",
            alarm_description="Lambda function errors >= 5 within 5 minutes.",
            metric=self.api_function.metric_errors(period=Duration.minutes(5)),
            threshold=5,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        lambda_errors_alarm.add_alarm_action(cloudwatch_actions.SnsAction(alarm_topic))

        apigw_5xx_alarm = cloudwatch.Alarm(
            self,
            "ApiGateway5xxAlarm",
            alarm_name="vindicara-api-5xx",
            alarm_description="API Gateway 5XX responses >= 5 within 5 minutes.",
            metric=cloudwatch.Metric(
                namespace="AWS/ApiGateway",
                metric_name="5XXError",
                dimensions_map={"ApiId": self.http_api.http_api_id},
                statistic="Sum",
                period=Duration.minutes(5),
            ),
            threshold=5,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        apigw_5xx_alarm.add_alarm_action(cloudwatch_actions.SnsAction(alarm_topic))
