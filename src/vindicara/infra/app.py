"""CDK application entry point."""

import os

import aws_cdk as cdk

from vindicara.infra.stacks.api_stack import APIStack
from vindicara.infra.stacks.data_stack import DataStack
from vindicara.infra.stacks.events_stack import EventsStack
from vindicara.infra.stacks.ops_chain_stack import OpsChainStack
from vindicara.infra.stacks.site_stack import SiteStack

app = cdk.App()

account = os.environ.get("CDK_DEFAULT_ACCOUNT", os.environ.get("VINDICARA_AWS_ACCOUNT_ID", ""))
workload_region = os.environ.get(
    "CDK_DEFAULT_REGION", os.environ.get("VINDICARA_AWS_REGION", "us-west-2")
)
site_region = "us-east-1"

if not account:
    raise RuntimeError(
        "AWS account ID required. Set CDK_DEFAULT_ACCOUNT or VINDICARA_AWS_ACCOUNT_ID environment variable."
    )

env_workload = cdk.Environment(account=account, region=workload_region)
env_site = cdk.Environment(account=account, region=site_region)

data = DataStack(app, "VindicaraData", env=env_workload)
events_stack = EventsStack(app, "VindicaraEvents", env=env_workload)
ops_chain = OpsChainStack(app, "VindicaraOpsChain", env=env_workload)

api_stack = APIStack(
    app,
    "VindicaraAPI",
    policies_table=data.policies_table,
    evaluations_table=data.evaluations_table,
    api_keys_table=data.api_keys_table,
    audit_bucket=data.audit_bucket,
    event_bus=events_stack.event_bus,
    env=env_workload,
)
# The API Lambda emits AgDR records into the ops chain on every request.
ops_chain.ops_chain_table.grant_write_data(api_stack.api_function)
api_stack.api_function.add_environment("VINDICARA_OPS_CHAIN_TABLE", ops_chain.ops_chain_table.table_name)

# SiteStack lives in us-east-1 because CloudFront ACM certs must live there.
# The dashboard origin domain is composed from VindicaraAPI's HTTP API ID,
# which is only known after the API stack deploys. Pass it via context:
#   cdk deploy VindicaraSite -c api_endpoint_id=<api-id-from-stage-2>
# The "tbd" placeholder lets `cdk synth` succeed before Stage 2 has run.
api_endpoint_id = app.node.try_get_context("api_endpoint_id") or "tbd"

SiteStack(
    app,
    "VindicaraSite",
    api_endpoint_id=api_endpoint_id,
    api_region=workload_region,
    env=env_site,
)

app.synth()
