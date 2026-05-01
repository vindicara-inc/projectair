"""Lambda function and API Gateway for Vindicara API."""

from aws_cdk import Duration, Stack
from aws_cdk import aws_apigatewayv2 as apigw
from aws_cdk import aws_apigatewayv2_integrations as integrations
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cloudwatch_actions
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_events as events
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
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
        audit_bucket: s3.Bucket,
        event_bus: events.EventBus,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

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
        audit_bucket.grant_write(self.api_function)
        event_bus.grant_put_events_to(self.api_function)

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
