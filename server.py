"""CineAgent server: ADK web UI and API, plus the platform's UCP profile.

Merchants fetch /.well-known/ucp to get the public key that verifies our AP2 mandates.
Run locally:  uvicorn server:app --port 8080
"""

import os

import uvicorn
from google.adk.cli.fast_api import get_fast_api_app

from cineagent.trusted_platform import platform_profile

app = get_fast_api_app(
    agents_dir=os.path.dirname(os.path.abspath(__file__)),
    # Pin every service to in-memory so local runs never pick up Agent Platform settings
    # from the environment (for example GOOGLE_CLOUD_AGENT_ENGINE_ID).
    session_service_uri="memory://",
    memory_service_uri="memory://",
    artifact_service_uri="memory://",
    use_local_storage=False,
    web=True,
)


@app.get("/.well-known/ucp")
def ucp_profile() -> dict:
    return platform_profile()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
