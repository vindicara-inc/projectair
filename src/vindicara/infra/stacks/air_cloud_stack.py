"""AIR Cloud stack: DynamoDB tables + Lambda + API Gateway.

Deployed independently from the Vindicara engine API. Serves the
hosted capsule ingest surface that the AIR dashboard connects to.
"""

from aws_cdk import Duration, RemovalPolicy, Stack
from aws_cdk import aws_apigatewayv2 as apigw
from aws_cdk import aws_apigatewayv2_integrations as integrations
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cloudwatch_actions
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as sns_subscriptions
from constructs import Construct

ALARM_EMAIL = "kev.minn9@gmail.com"


class AirCloudStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.capsules_table = dynamodb.Table(
            self,
            "CapsulesTable",
            table_name="air-cloud-capsules",
            partition_key=dynamodb.Attribute(
                name="workspace_id",
                type=dynamodb.AttributeType.STRING,
            ),
            sort_key=dynamodb.Attribute(
                name="step_id",
                type=dynamodb.AttributeType.STRING,
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
            removal_policy=RemovalPolicy.RETAIN,
        )

        self.workspaces_table = dynamodb.Table(
            self,
            "WorkspacesTable",
            table_name="air-cloud-workspaces",
            partition_key=dynamodb.Attribute(
                name="workspace_id",
                type=dynamodb.AttributeType.STRING,
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
            removal_policy=RemovalPolicy.RETAIN,
        )

        self.api_keys_table = dynamodb.Table(
            self,
            "ApiKeysTable",
            table_name="air-cloud-api-keys",
            partition_key=dynamodb.Attribute(
                name="key_id",
                type=dynamodb.AttributeType.STRING,
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
            removal_policy=RemovalPolicy.RETAIN,
        )
        self.api_keys_table.add_global_secondary_index(
            index_name="by_key_hash",
            partition_key=dynamodb.Attribute(
                name="key_hash",
                type=dynamodb.AttributeType.STRING,
            ),
            projection_type=dynamodb.ProjectionType.ALL,
        )

        self.api_function = lambda_.Function(
            self,
            "CloudFunction",
            function_name="air-cloud-api",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="vindicara.cloud.lambda_handler.handler",
            code=lambda_.Code.from_asset("lambda_package"),
            memory_size=256,
            timeout=Duration.seconds(30),
            environment={
                "AIR_CLOUD_CAPSULES_TABLE": self.capsules_table.table_name,
                "AIR_CLOUD_WORKSPACES_TABLE": self.workspaces_table.table_name,
                "AIR_CLOUD_API_KEYS_TABLE": self.api_keys_table.table_name,
            },
            log_retention=logs.RetentionDays.ONE_MONTH,
            tracing=lambda_.Tracing.ACTIVE,
        )

        self.capsules_table.grant_read_write_data(self.api_function)
        self.workspaces_table.grant_read_write_data(self.api_function)
        self.api_keys_table.grant_read_write_data(self.api_function)

        self.http_api = apigw.HttpApi(
            self,
            "AirCloudAPI",
            api_name="air-cloud-api",
            default_integration=integrations.HttpLambdaIntegration(
                "CloudLambdaIntegration",
                handler=self.api_function,
            ),
            cors_preflight=apigw.CorsPreflightOptions(
                allow_headers=["*"],
                allow_methods=[
                    apigw.CorsHttpMethod.GET,
                    apigw.CorsHttpMethod.POST,
                    apigw.CorsHttpMethod.DELETE,
                    apigw.CorsHttpMethod.OPTIONS,
                ],
                allow_origins=["*"],
            ),
        )

        alarm_topic = sns.Topic(
            self,
            "CloudAlarmTopic",
            topic_name="air-cloud-alarms",
            display_name="AIR Cloud workload alarms",
        )
        alarm_topic.add_subscription(
            sns_subscriptions.EmailSubscription(ALARM_EMAIL),
        )

        lambda_errors = cloudwatch.Alarm(
            self,
            "CloudLambdaErrors",
            alarm_name="air-cloud-lambda-errors",
            alarm_description="AIR Cloud Lambda errors >= 5 in 5 min.",
            metric=self.api_function.metric_errors(
                period=Duration.minutes(5),
            ),
            threshold=5,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        lambda_errors.add_alarm_action(
            cloudwatch_actions.SnsAction(alarm_topic),
        )

        apigw_5xx = cloudwatch.Alarm(
            self,
            "CloudApiGateway5xx",
            alarm_name="air-cloud-api-5xx",
            alarm_description="AIR Cloud API 5XX >= 5 in 5 min.",
            metric=cloudwatch.Metric(
                namespace="AWS/ApiGateway",
                metric_name="5XXError",
                dimensions_map={
                    "ApiId": self.http_api.http_api_id,
                },
                statistic="Sum",
                period=Duration.minutes(5),
            ),
            threshold=5,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )
        apigw_5xx.add_alarm_action(
            cloudwatch_actions.SnsAction(alarm_topic),
        )
