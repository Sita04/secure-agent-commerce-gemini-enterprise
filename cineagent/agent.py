"""CineAgent: books movie tickets across UCP merchants and pays with AP2 mandates."""

import json
import os

from google.adk.agents import Agent
from google.adk.models import Gemini
from google.adk.tools import FunctionTool
from google.genai import types

from . import trusted_platform as platform


async def discover_theaters() -> str:
    """Discover theater merchants and their capabilities via UCP."""
    theaters = []
    for url in platform.MERCHANT_URLS:
        try:
            m = await platform.discover(url)
            theaters.append({k: m[k] for k in ("url", "capabilities", "ap2_required")})
        except Exception as e:  # noqa: BLE001  e.g. 403 when Agent Gateway blocks the merchant
            theaters.append({"url": url, "unavailable": platform.short_error(e)})
    return json.dumps(theaters)


async def search_movies(query: str = "") -> str:
    """Search movies and showtimes across all theaters. Use '' to list everything."""
    results = []
    for url in platform.MERCHANT_URLS:
        try:
            found = await platform.call(
                url, "search_catalog", {"catalog": {"query": query}}
            )
        except Exception as e:  # noqa: BLE001
            results.append({"theater": url, "unavailable": platform.short_error(e)})
            continue
        for p in found.get("products", []):
            results.append(
                {
                    "theater": url,
                    "movie": p["title"],
                    "showtimes": [
                        {
                            "showtime_id": v["id"],
                            "format": v["options"][0]["label"],
                            "time": v["options"][1]["label"],
                            "price_cents": v["price"]["amount"],
                        }
                        for v in p["variants"]
                    ],
                }
            )
    return json.dumps(results)


async def create_checkout(
    merchant_url: str, showtime_id: str, quantity: int = 1
) -> str:
    """Create a checkout for tickets. The merchant signs the cart and total."""
    try:
        checkout = await platform.call(merchant_url, "create_checkout", {"checkout": {
            "line_items": [{"item": {"id": showtime_id}, "quantity": quantity}]}})
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": platform.short_error(e)})
    if "id" not in checkout:
        return json.dumps(checkout.get("messages", checkout))
    # UCP: the platform MUST verify the merchant's signature before showing the checkout.
    if not await platform.verified_checkout_jwt(merchant_url, checkout):
        return json.dumps({"error": "merchant_authorization_invalid"})
    return json.dumps(
        {
            "checkout_id": checkout["id"],
            "items": [
                f"{li['quantity']} x {li['item']['title']}"
                for li in checkout["line_items"]
            ],
            "total_cents": platform.total(checkout),
            "merchant_signature": "verified",
        }
    )


async def complete_purchase(
    checkout_id: str, merchant_url: str, total_cents: int
) -> str:
    """Pay `total_cents` for a checkout with AP2 mandates. The user must approve first."""
    # This body runs only after the user approves this exact call (see require_confirmation below).
    checkout = await platform.call(merchant_url, "get_checkout", {"id": checkout_id})
    checkout_jwt = await platform.verified_checkout_jwt(merchant_url, checkout)
    if not checkout_jwt:
        return json.dumps({"error": "merchant_authorization_invalid"})
    # The user approved total_cents. Sign only if it is exactly what the merchant signed.
    if platform.total(checkout) != total_cents:
        return json.dumps(
            {
                "error": "approved amount does not match the merchant-signed total",
                "merchant_total_cents": platform.total(checkout),
            }
        )
    checkout_mandate, payment_mandate = platform.sign_mandates(
        checkout, checkout_jwt, merchant_url
    )
    result = await platform.call(
        merchant_url,
        "complete_checkout",
        await platform.completion_request(
            checkout_id, merchant_url, checkout_mandate, payment_mandate
        ),
    )
    if result.get("status") != "completed":
        return json.dumps(result.get("messages", result))
    return json.dumps(
        {
            "status": "completed",
            "order_id": result["order"]["id"],
            "checkout_receipt": "signed"
            if result["ap2"].get("checkout_receipt")
            else "missing",
        }
    )


root_agent = Agent(
    name="cineagent",
    model=Gemini(
        model=os.environ.get("AGENT_MODEL", "gemini-3.8-flash"),
        retry_options=types.HttpRetryOptions(attempts=5),
    ),
    description="Movie ticket booking agent using UCP and AP2.",
    instruction="""You are CineAgent. You find and book movie tickets across theaters.

- Call discover_theaters first, then search_movies.
- Prices are in cents (1500 = $15.00). Never invent data; only state what tools return.
- To buy: call create_checkout, tell the user the total, then call complete_purchase with
  the checkout's total_cents. The user approves the payment in a confirmation dialog.
- Never claim a purchase succeeded unless complete_purchase returned status "completed".
- A theater marked "unavailable" is blocked (for example by your organization's Agent Gateway
  policy). Tell the user and do not use it.
- If a tool returns an error or is denied, report it. Never retry to get around a refusal.
""",
    tools=[
        discover_theaters,
        search_movies,
        create_checkout,
        # ADK pauses before running this tool until the user approves the exact
        # arguments (merchant, checkout, amount). The model cannot approve for them.
        FunctionTool(complete_purchase, require_confirmation=True),
    ],
)
