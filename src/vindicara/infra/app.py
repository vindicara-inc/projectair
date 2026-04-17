"""CDK application entry point."""

import os

import aws_cdk as cdk

from vindicara.infra.stacks.api_stack import APIStack
from vindicara.infra.stacks.data_stack import DataStack
from vindicara.infra.stacks.events_stack import EventsStack

app = cdk.App()

account = os.environ.get("CDK_DEFAULT_ACCOUNT", os.environ.get("VINDICARA_AWS_ACCOUNT_ID", ""))
region = os.environ.get("CDK_DEFAULT_REGION", os.environ.get("VINDICARA_AWS_REGION", "us-east-1"))

if not account:
    raise RuntimeError(
        "AWS account ID required. Set CDK_DEFAULT_ACCOUNT or VINDICARA_AWS_ACCOUNT_ID environment variable."
    )

env = cdk.Environment(account=account, region=region)

data = DataStack(app, "VindicaraData", env=env)
events_stack = EventsStack(app, "VindicaraEvents", env=env)

APIStack(
    app,
    "VindicaraAPI",
    policies_table=data.policies_table,
    evaluations_table=data.evaluations_table,
    api_keys_table=data.api_keys_table,
    audit_bucket=data.audit_bucket,
    event_bus=events_stack.event_bus,
    env=env,
)

app.synth()
