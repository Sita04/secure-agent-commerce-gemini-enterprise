"""Deploy CineAgent to Agent Runtime with Agent Identity, behind an egress Agent Gateway.

Called by `./setup.sh deploy`. Prints the reasoning engine resource name.
"""

import os
import sys

import vertexai
from google.adk.sessions import InMemorySessionService
from vertexai import types
from vertexai.agent_engines import AdkApp

from cineagent.agent import root_agent

PROJECT, REGION = os.environ["PROJECT_ID"], os.environ["REGION"]
AP2_WHEEL = os.environ[
    "AP2_WHEEL"
]  # AP2 is not on PyPI; ship the pinned release as a wheel

client = vertexai.Client(
    project=PROJECT, location=REGION, http_options={"api_version": "v1beta1"}
)

# ADK tool confirmation does not survive the managed (Vertex AI) session service, so this demo
# keeps sessions in memory on a single instance. See https://adk.dev/tools-custom/confirmation/
app = AdkApp(agent=root_agent, session_service_builder=lambda: InMemorySessionService())

config = {
        "display_name": "day16-cineagent",
        "description": "Advent of Agents Day 16: UCP shopping agent that pays with AP2 mandates",
        "staging_bucket": f"gs://{os.environ['STAGING_BUCKET']}",
        "requirements": [
            "google-cloud-aiplatform[agent_engines,adk]==2.5.0",
            "google-adk==2.11.0",
            "mcp==2.3.0",
            "ucp-sdk==0.5.0",
            "rfc8785==0.1.4",
            "httpx==0.28.1",
            AP2_WHEEL,
        ],
        "extra_packages": ["cineagent", AP2_WHEEL],
        "identity_type": types.IdentityType.AGENT_IDENTITY,
        "agent_gateway_config": {
            "agent_to_anywhere_config": {
                "agent_gateway": f"projects/{PROJECT}/locations/{REGION}/agentGateways/{os.environ['GATEWAY']}"
            }
        },
        "min_instances": 1,
        "max_instances": 1,
        "env_vars": {
            "GOOGLE_CLOUD_LOCATION": "global",  # gemini-3.8-flash is served from the global endpoint
            "GOOGLE_API_USE_CLIENT_CERTIFICATE": "false",
            "GOOGLE_API_USE_MTLS_ENDPOINT": "never",
            "MERCHANT_URLS": os.environ["MERCHANT_URLS"],
            "PLATFORM_PROFILE_URL": os.environ["PLATFORM_PROFILE_URL"],
            "PLATFORM_SIGNING_KEY": {
                "secret": os.environ["PLATFORM_KEY_SECRET"],
                "version": "latest",
            },
        },
}
remote = client.agent_engines.create(agent=app, config=config)
print(remote.api_resource.name)
sys.stdout.flush()
