"""Stripe webhook Lambda behind a Function URL.

Receives checkout.session.completed events and provisions Auth0 users
with API keys stored in the shared api-keys DynamoDB table.
"""

from aws_cdk import CfnOutput, Duration, Environment, Stack
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_lambda as lambda_
from constructs import Construct


class WebhookStack(Stack):
    """Stripe webhook provisioning pipeline."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        api_keys_table: dynamodb.ITable,
        stripe_webhook_secret: str,
        auth0_domain: str,
        auth0_mgmt_client_id: str,
        auth0_mgmt_client_secret: str,
        auth0_spa_client_id: str,
        env: Environment | None = None,
    ) -> None:
        super().__init__(scope, construct_id, env=env)

        webhook_fn = lambda_.Function(
            self,
            "StripeWebhookFn",
            function_name="vindicara-stripe-webhook",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="handler.lambda_handler",
            code=lambda_.Code.from_asset("src/vindicara/webhooks"),
            memory_size=128,
            timeout=Duration.seconds(30),
            environment={
                "STRIPE_WEBHOOK_SECRET": stripe_webhook_secret,
                "AUTH0_DOMAIN": auth0_domain,
                "AUTH0_MGMT_CLIENT_ID": auth0_mgmt_client_id,
                "AUTH0_MGMT_CLIENT_SECRET": auth0_mgmt_client_secret,
                "AUTH0_SPA_CLIENT_ID": auth0_spa_client_id,
                "API_KEYS_TABLE": api_keys_table.table_name,
            },
        )

        api_keys_table.grant_write_data(webhook_fn)

        fn_url = webhook_fn.add_function_url(
            auth_type=lambda_.FunctionUrlAuthType.NONE,
        )

        self.webhook_url = fn_url

        CfnOutput(
            self,
            "WebhookUrl",
            value=fn_url.url,
            description="Stripe webhook endpoint URL. Add this in Stripe Dashboard → Webhooks.",
        )
