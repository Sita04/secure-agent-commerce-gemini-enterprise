"""A mock UCP merchant (one movie theater) served as an MCP server.

Implements the parts of UCP 2026-08-25 and AP2 v0.2 that matter for security:
- `/.well-known/ucp` profile with the merchant's public signing key
- every checkout signed with `ap2.merchant_authorization` (the price lock)
- `complete_checkout` only succeeds with mandates signed by a trusted platform,
  bound to the exact checkout this merchant signed

Run locally:  THEATER=meridian PORT=8081 python merchant/main.py
"""

import json
import logging
import os
import uuid
from typing import Any

import httpx
import rfc8785
import uvicorn
from ap2.sdk.generated.checkout_mandate import CheckoutMandate
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.jwt_helper import create_jwt
from ap2.sdk.mandate import MandateClient
from ap2.sdk.receipt_wrapper import ReceiptClient
from ap2.sdk.utils import compute_sha256_b64url
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from ucp_sdk.models.schemas.common.payment_ap2_mandate import Checkout
from ucp_sdk.models.schemas.profile import BusinessSchema
from ucp_sdk.models.schemas.shopping.catalog_search import SearchResponse

logging.getLogger("httpx").setLevel(logging.WARNING)  # keep the terminal to the protocol story

UCP_VERSION = "2026-08-25"
UCP_SPEC = f"https://ucp.dev/{UCP_VERSION}"

THEATERS = {
    "meridian": {
        "name": "Meridian Cinemas",
        "movies": [
            {
                "id": "opp",
                "title": "Oppenheimer",
                "categories": ["Drama", "History"],
                "showtimes": [
                    {
                        "id": "st_opp_7pm_imax",
                        "format": "IMAX",
                        "time": "7:00 PM",
                        "price": 2200,
                        "seats": 45,
                    },
                    {
                        "id": "st_opp_930pm",
                        "format": "Standard",
                        "time": "9:30 PM",
                        "price": 1500,
                        "seats": 80,
                    },
                ],
            },
            {
                "id": "dune3",
                "title": "Dune: Part Three",
                "categories": ["Sci-Fi", "Action"],
                "showtimes": [
                    {
                        "id": "st_dune_8pm_imax",
                        "format": "IMAX",
                        "time": "8:00 PM",
                        "price": 2200,
                        "seats": 30,
                    }
                ],
            },
        ],
    },
    "starlight": {
        "name": "StarLight Theaters",
        "movies": [
            {
                "id": "opp",
                "title": "Oppenheimer",
                "categories": ["Drama", "History"],
                "showtimes": [
                    {
                        "id": "st_opp_6pm_atmos",
                        "format": "Dolby Atmos",
                        "time": "6:00 PM",
                        "price": 1800,
                        "seats": 60,
                    }
                ],
            },
            {
                "id": "spider",
                "title": "Spider-Verse",
                "categories": ["Animation", "Action"],
                "showtimes": [
                    {
                        "id": "st_spider_4pm",
                        "format": "Standard",
                        "time": "4:00 PM",
                        "price": 1200,
                        "seats": 100,
                    }
                ],
            },
        ],
    },
}

THEATER = THEATERS[os.environ.get("THEATER", "meridian")]
PORT = int(os.environ.get("PORT", "8081"))
PUBLIC_URL = os.environ.get("PUBLIC_URL", f"http://127.0.0.1:{PORT}").rstrip("/")
# Platforms (shopping agents) whose mandate signatures this merchant accepts.
# The merchant reads each platform's public keys from its UCP profile URL.
TRUSTED_PLATFORMS = {
    p.strip()
    for p in os.environ.get(
        "TRUSTED_PLATFORM_PROFILES", "http://127.0.0.1:8080/.well-known/ucp"
    ).split(",")
    if p.strip()
}

# The merchant's signing key. On Cloud Run it comes from Secret Manager so all
# instances share it; locally a fresh key is generated at startup.
if os.environ.get("MERCHANT_SIGNING_KEY"):
    KEY = JWK.from_json(os.environ["MERCHANT_SIGNING_KEY"])
else:
    KEY = JWK.generate(
        kty="EC", crv="P-256", kid=f"{os.environ.get('THEATER', 'meridian')}-1"
    )

PAYMENT_HANDLERS = {
    "com.example.card": [
        {
            "id": "card_handler",
            "version": UCP_VERSION,
            "available_instruments": [{"type": "card"}],
            "config": {},
        }
    ]
}

sessions: dict[str, dict] = {}  # checkout id -> checkout
signed_checkouts: dict[str, str] = {}  # checkout id -> merchant-signed checkout JWT

mcp = MCPServer(
    THEATER["name"], instructions="UCP shopping service for a movie theater."
)


# ── Signing helpers (JWS detached content over the JCS-canonicalized checkout) ──


def sign_checkout(checkout: dict) -> None:
    """Add `ap2.merchant_authorization`: this merchant's signature over the checkout."""
    payload = rfc8785.dumps({k: v for k, v in checkout.items() if k != "ap2"})
    jws = JWS(payload)
    jws.add_signature(
        KEY, alg="ES256", protected=json.dumps({"alg": "ES256", "kid": KEY.kid})
    )
    checkout_jwt = jws.serialize(compact=True)
    header, _, signature = checkout_jwt.split(".")
    checkout["ap2"] = {"merchant_authorization": f"{header}..{signature}"}
    signed_checkouts[checkout["id"]] = checkout_jwt


def log(text: str) -> None:
    print(f"[{THEATER['name']}] {text}", flush=True)


def error(code: str, content: str) -> dict:
    """A UCP business outcome error (returned as a result, not a protocol error)."""
    log(f"REJECTED -> {code}: {content}")
    return {
        "ucp": {"version": UCP_VERSION, "status": "error"},
        "messages": [
            {
                "type": "error",
                "code": code,
                "content": content,
                "severity": "unrecoverable",
            }
        ],
    }


def platform_keys(meta: dict) -> list[dict]:
    """Fetch public keys from the calling platform's UCP profile, if we trust it."""
    profile_url = (meta or {}).get("ucp-agent", {}).get("profile", "")
    if profile_url not in TRUSTED_PLATFORMS:
        return []
    return httpx.get(profile_url, timeout=10).json().get("keys", [])


def ucp_meta(*capabilities: str) -> dict:
    return {
        "version": UCP_VERSION,
        "capabilities": {c: [{"version": UCP_VERSION}] for c in capabilities},
    }


def find_showtime(showtime_id: str):
    for movie in THEATER["movies"]:
        for st in movie["showtimes"]:
            if st["id"] == showtime_id:
                return movie, st
    return None, None


# ── UCP discovery ──


@mcp.custom_route("/.well-known/ucp", methods=["GET"])
async def profile(_: Request) -> JSONResponse:
    def cap(name, path, schema, **extra):
        return {
            name: [
                {
                    "version": UCP_VERSION,
                    "spec": f"{UCP_SPEC}/specification/{path}",
                    "schema": f"{UCP_SPEC}/schemas/{schema}",
                    **extra,
                }
            ]
        }

    body = {
        "ucp": {
            "version": UCP_VERSION,
            "services": {
                "dev.ucp.shopping": [
                    {
                        "version": UCP_VERSION,
                        "spec": f"{UCP_SPEC}/specification/overview",
                        "transport": "mcp",
                        "schema": f"{UCP_SPEC}/services/shopping/mcp.openrpc.json",
                        "endpoint": f"{PUBLIC_URL}/mcp",
                    }
                ]
            },
            "capabilities": {
                **cap(
                    "dev.ucp.shopping.catalog.search",
                    "shopping/catalog/search",
                    "shopping/catalog_search.json",
                ),
                **cap(
                    "dev.ucp.shopping.checkout",
                    "shopping/checkout",
                    "shopping/checkout.json",
                ),
                **cap(
                    "dev.ucp.common.payment.ap2_mandate",
                    "payment/extensions/ap2-mandates",
                    "common/payment_ap2_mandate.json",
                    extends="dev.ucp.shopping.checkout",
                    config={"vp_formats_supported": {"dc+sd-jwt": {}}},
                ),
            },
            "payment_handlers": PAYMENT_HANDLERS,
        },
        "keys": [json.loads(KEY.export_public())],
    }
    BusinessSchema.model_validate(body)
    return JSONResponse(body)


# ── UCP shopping tools (MCP binding) ──


@mcp.tool()
def search_catalog(meta: dict, catalog: dict) -> dict[str, Any]:
    """Search this theater's movies and showtimes."""
    q = catalog.get("query", "").lower()
    products = []
    for m in THEATER["movies"]:
        if (
            q
            and q not in m["title"].lower()
            and not any(q in c.lower() for c in m["categories"])
        ):
            continue
        prices = [st["price"] for st in m["showtimes"]]
        products.append(
            {
                "id": m["id"],
                "title": m["title"],
                "description": {"plain": f"{m['title']} at {THEATER['name']}"},
                "categories": [
                    {"value": c, "taxonomy": "merchant"} for c in m["categories"]
                ],
                "price_range": {
                    "min": {"amount": min(prices), "currency": "USD"},
                    "max": {"amount": max(prices), "currency": "USD"},
                },
                "variants": [
                    {
                        "id": st["id"],
                        "title": f"{st['format']} {st['time']}",
                        "description": {
                            "plain": f"{st['format']} showing at {st['time']}"
                        },
                        "options": [
                            {"name": "format", "label": st["format"]},
                            {"name": "time", "label": st["time"]},
                        ],
                        "price": {"amount": st["price"], "currency": "USD"},
                        "availability": {"available": st["seats"] > 0},
                        "metadata": {"seats_available": st["seats"]},
                    }
                    for st in m["showtimes"]
                ],
            }
        )
    result = {"ucp": ucp_meta("dev.ucp.shopping.catalog.search"), "products": products}
    SearchResponse.model_validate(result)
    return result


@mcp.tool()
def create_checkout(meta: dict, checkout: dict) -> dict[str, Any]:
    """Create a checkout for showtime tickets. The response is signed by the merchant."""
    line_items, subtotal = [], 0
    for li in checkout.get("line_items", []):
        movie, st = find_showtime(li["item"]["id"])
        if not st:
            continue
        qty = int(li.get("quantity", 1))
        amount = st["price"] * qty
        subtotal += amount
        line_items.append(
            {
                "id": f"li_{uuid.uuid4().hex[:8]}",
                "item": {
                    "id": st["id"],
                    "title": f"{movie['title']} ({st['format']}, {st['time']})",
                    "price": st["price"],
                },
                "quantity": qty,
                "totals": [
                    {"type": "subtotal", "amount": amount},
                    {"type": "total", "amount": amount},
                ],
            }
        )
    if not line_items:
        return error("invalid_line_items", "No valid showtimes in checkout")
    tax = int(subtotal * 0.08)
    session = {
        "ucp": {
            **ucp_meta(
                "dev.ucp.shopping.checkout", "dev.ucp.common.payment.ap2_mandate"
            ),
            "payment_handlers": PAYMENT_HANDLERS,
        },
        "id": f"chk_{uuid.uuid4().hex[:12]}",
        "status": "ready_for_complete",
        "currency": "USD",
        "line_items": line_items,
        "totals": [
            {"type": "subtotal", "display_text": "Subtotal", "amount": subtotal},
            {"type": "tax", "display_text": "Tax", "amount": tax},
            {"type": "total", "display_text": "Total", "amount": subtotal + tax},
        ],
        "links": [{"type": "terms_of_service", "url": f"{PUBLIC_URL}/terms"}],
    }
    sign_checkout(session)
    sessions[session["id"]] = session
    Checkout.model_validate(session)
    items = ", ".join(f"{li['quantity']} x {li['item']['title']}" for li in line_items)
    log(f"create_checkout {session['id']}: {items} = ${(subtotal + tax) / 100:.2f}. "
        f"Signed it with merchant key '{KEY.kid}' (ap2.merchant_authorization), which locks the price.")
    return session


@mcp.tool()
def get_checkout(meta: dict, id: str) -> dict[str, Any]:
    """Get the current, merchant-signed state of a checkout."""
    return sessions.get(id) or error("not_found", f"No checkout {id}")


@mcp.tool()
def complete_checkout(meta: dict, id: str, checkout: dict) -> dict[str, Any]:
    """Complete a checkout. Requires AP2 mandates from a trusted platform."""
    session = sessions.get(id)
    if not session:
        return error("not_found", f"No checkout {id}")
    if session["status"] == "completed":
        return error(
            "checkout_already_completed",
            "This checkout was already paid; mandates are single use",
        )

    checkout_mandate = checkout.get("ap2", {}).get("checkout_mandate")
    instruments = checkout.get("payment", {}).get("instruments", [])
    if not checkout_mandate or not instruments:
        return error(
            "mandate_required",
            "complete_checkout needs ap2.checkout_mandate and a payment mandate",
        )
    payment_mandate = instruments[0].get("credential", {}).get("token", "")

    keys = platform_keys(meta)
    if not keys:
        return error(
            "agent_missing_key",
            "Unknown platform, or its UCP profile publishes no keys",
        )

    cm = pm = None
    reason = "No platform key verified the mandates"
    for k in keys:  # verify against the platform's published keys
        try:
            cm = (
                MandateClient()
                .verify(checkout_mandate, JWK(**k), payload_type=CheckoutMandate)
                .mandate_payload
            )
            pm = (
                MandateClient()
                .verify(payment_mandate, JWK(**k), payload_type=PaymentMandate)
                .mandate_payload
            )
            break
        except Exception as e:  # noqa: BLE001
            reason = str(e)
    if cm is None or pm is None:
        code = (
            "mandate_expired"
            if "expir" in reason.lower()
            else "mandate_invalid_signature"
        )
        return error(code, reason)

    # The mandates must point at exactly the checkout this merchant signed.
    signed_jwt = signed_checkouts[id]
    checkout_hash = compute_sha256_b64url(signed_jwt)
    total = next(t["amount"] for t in session["totals"] if t["type"] == "total")
    if (
        cm.checkout_jwt != signed_jwt
        or cm.checkout_hash != checkout_hash
        or pm.transaction_id != checkout_hash
        or pm.payment_amount.amount != total
    ):
        return error(
            "mandate_scope_mismatch",
            "The mandates are bound to a different checkout or amount",
        )

    log(f"complete_checkout {id}: platform key fetched from {meta['ucp-agent']['profile']}; both mandate "
        f"signatures valid; both bound to the checkout hash I signed ({checkout_hash[:12]}...); amount {total} matches.")
    order_id = f"ord_{uuid.uuid4().hex[:8]}"
    session["status"] = "completed"
    session["order"] = {
        "id": order_id,
        "label": THEATER["name"],
        "permalink_url": f"{PUBLIC_URL}/orders/{order_id}",
    }
    sign_checkout(session)
    # AP2 v0.2: the merchant returns a signed Checkout Receipt bound to the mandate.
    receipt = ReceiptClient().create_checkout_receipt(
        merchant=THEATER["name"],
        reference=compute_sha256_b64url(
            MandateClient().get_closed_mandate_jwt(checkout_mandate)
        ),
        order_id=order_id,
    )
    receipt_jwt = create_jwt(
        {"alg": "ES256", "kid": KEY.kid, "typ": "JWT"},
        receipt.model_dump(mode="json", exclude_none=True),
        KEY,
    )
    log(f"ORDER {order_id} created; returned a signed AP2 Checkout Receipt.")
    return {**session, "ap2": {**session["ap2"], "checkout_receipt": receipt_jwt}}


app = mcp.streamable_http_app(
    stateless_http=True,
    json_response=True,
    host="0.0.0.0",
    # Cloud Run fronts the container with its own hostname; allow any Host header.
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="warning")
