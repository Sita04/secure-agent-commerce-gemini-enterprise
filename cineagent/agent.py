"""CineAgent: books movie tickets across UCP merchants and pays with AP2 mandates.

Every tool returns `protocol_steps`: a plain-language account of what happened at the
protocol level (UCP discovery, merchant signatures, AP2 mandates). The agent shows them
to the user, and the same lines are printed in the terminal running the agent.
"""

import json
import os

from google.adk.agents import Agent
from google.adk.models import Gemini
from google.adk.tools import FunctionTool
from google.genai import types

from . import trusted_platform as platform

step = platform.step


async def discover_theaters() -> str:
    """Discover theater merchants and their capabilities via UCP."""
    theaters, steps = [], []
    for url in platform.MERCHANT_URLS:
        try:
            m = await platform.discover(url)
        except Exception as e:  # noqa: BLE001  e.g. 403 when Agent Gateway blocks the merchant
            reason = platform.short_error(e)
            theaters.append({"url": url, "unavailable": reason})
            steps.append(
                step(
                    f"UCP: could not read {url}/.well-known/ucp ({reason}). Treating it as unavailable."
                )
            )
            continue
        theaters.append({k: m[k] for k in ("url", "capabilities", "ap2_required")})
        kids = ", ".join(k.get("kid", "?") for k in m["keys"])
        steps.append(
            step(
                f"UCP: read {url}/.well-known/ucp. It supports {', '.join(c.split('.')[-1] for c in m['capabilities'])}"
                f"{' and REQUIRES AP2 mandates for payment' if m['ap2_required'] else ''}. "
                f"Saved its public signing key ({kids}) to check its signatures later."
            )
        )
    return json.dumps({"theaters": theaters, "protocol_steps": steps})


async def search_movies(query: str = "") -> str:
    """Search movies and showtimes across all theaters. Use '' to list everything."""
    results, steps = [], []
    for url in platform.MERCHANT_URLS:
        try:
            found = await platform.call(
                url, "search_catalog", {"catalog": {"query": query}}
            )
        except Exception as e:  # noqa: BLE001
            results.append({"theater": url, "unavailable": platform.short_error(e)})
            continue
        steps.append(
            step(
                f"UCP: called the search_catalog MCP tool on {url} ({len(found.get('products', []))} movies)."
            )
        )
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
    return json.dumps({"results": results, "protocol_steps": steps})


async def create_checkout(
    merchant_url: str, showtime_id: str, quantity: int = 1
) -> str:
    """Create a checkout for tickets. The merchant signs the cart and total."""
    try:
        checkout = await platform.call(
            merchant_url,
            "create_checkout",
            {
                "checkout": {
                    "line_items": [{"item": {"id": showtime_id}, "quantity": quantity}]
                }
            },
        )
    except Exception as e:  # noqa: BLE001
        return json.dumps({"error": platform.short_error(e)})
    if "id" not in checkout:
        return json.dumps(checkout.get("messages", checkout))
    total = platform.total(checkout)
    steps = [
        step(
            f"UCP: called create_checkout on {merchant_url}. The merchant returned checkout {checkout['id']} "
            f"for ${total / 100:.2f} (including tax)."
        )
    ]
    # UCP: the platform MUST verify the merchant's signature before showing the checkout.
    if not await platform.verified_checkout_jwt(merchant_url, checkout):
        steps.append(
            step(
                "AP2: the merchant's signature on this checkout is INVALID. Refusing to show it."
            )
        )
        return json.dumps(
            {"error": "merchant_authorization_invalid", "protocol_steps": steps}
        )
    sig = checkout["ap2"]["merchant_authorization"]
    steps.append(
        step(
            f"AP2: the checkout carries the merchant's signature (ap2.merchant_authorization = {sig[:18]}...{sig[-8:]}). "
            "Verified it against the merchant's public key: the items and the total are locked, so nobody can change "
            "the price after this point without breaking the signature."
        )
    )
    return json.dumps(
        {
            "checkout_id": checkout["id"],
            "items": [
                f"{li['quantity']} x {li['item']['title']}"
                for li in checkout["line_items"]
            ],
            "total_cents": total,
            "protocol_steps": steps,
        }
    )


async def complete_purchase(
    checkout_id: str, merchant_url: str, total_cents: int
) -> str:
    """Pay `total_cents` for a checkout with AP2 mandates. The user must approve first."""
    # This body runs only after the user approves this exact call (see require_confirmation below).
    steps = [
        step(
            f"Human approval: you approved paying {total_cents} cents for checkout {checkout_id}. "
            "ADK paused this tool until you did; the model cannot approve on your behalf."
        )
    ]
    checkout = await platform.call(merchant_url, "get_checkout", {"id": checkout_id})
    checkout_jwt = await platform.verified_checkout_jwt(merchant_url, checkout)
    if not checkout_jwt:
        return json.dumps(
            {"error": "merchant_authorization_invalid", "protocol_steps": steps}
        )
    # The user approved total_cents. Sign only if it is exactly what the merchant signed.
    if platform.total(checkout) != total_cents:
        steps.append(
            step(
                f"Refused: you approved {total_cents} cents but the merchant-signed total is "
                f"{platform.total(checkout)} cents. Nothing was signed."
            )
        )
        return json.dumps(
            {
                "error": "approved amount does not match the merchant-signed total",
                "protocol_steps": steps,
            }
        )
    checkout_mandate, payment_mandate = platform.sign_mandates(
        checkout, checkout_jwt, merchant_url
    )
    checkout_hash = platform.compute_sha256_b64url(checkout_jwt)
    steps.append(
        step(
            f"AP2: deterministic platform code (not the model) signed two mandates with the platform key "
            f"'{platform.KEY.kid}': a Checkout Mandate (\"the user approved exactly this cart\") and a Payment Mandate "
            f'("pay {total_cents} {checkout["currency"]} to this merchant"). Both are SD-JWTs bound to the '
            f"checkout hash {checkout_hash[:12]}... and expire in 5 minutes."
        )
    )
    result = await platform.call(
        merchant_url,
        "complete_checkout",
        await platform.completion_request(
            checkout_id, merchant_url, checkout_mandate, payment_mandate
        ),
    )
    if result.get("status") != "completed":
        msg = result.get("messages", [{}])[0]
        steps.append(
            step(
                f"Merchant REJECTED the payment: {msg.get('code')} ({msg.get('content')})."
            )
        )
        return json.dumps({"status": "rejected", "error": msg, "protocol_steps": steps})
    steps.append(
        step(
            "Merchant: fetched the platform's public key from its UCP profile, verified both mandate signatures, "
            "checked that they point at the checkout it signed and match its total, then created order "
            f"{result['order']['id']} and returned a signed AP2 Checkout Receipt."
        )
    )
    return json.dumps(
        {
            "status": "completed",
            "order_id": result["order"]["id"],
            "protocol_steps": steps,
        }
    )


root_agent = Agent(
    name="cineagent",
    model=Gemini(
        model=os.environ.get("AGENT_MODEL", "gemini-3.8-flash"),
        retry_options=types.HttpRetryOptions(attempts=5),
    ),
    description="Movie ticket booking agent using UCP and AP2.",
    instruction="""You are CineAgent. You find and book movie tickets across theaters, and you are also
a teaching demo of secure agent payments (UCP + AP2).

- Call discover_theaters first, then search_movies.
- Prices are in cents (1500 = $15.00). Never invent data; only state what tools return.
- To buy: call create_checkout, tell the user the total, then call complete_purchase with the
  checkout's total_cents. The user approves the payment in a confirmation dialog.
- Every tool returns "protocol_steps". After each tool call, show them to the user under a short
  heading "Under the hood", as a numbered list, in order, without dropping details such as keys,
  hashes, and amounts. Then continue with your normal answer.
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
