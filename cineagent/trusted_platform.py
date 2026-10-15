"""Deterministic platform code: UCP discovery and calls, plus AP2 mandate signing.

This is the "trusted platform provider" from the UCP AP2 Mandates extension.
The model never sees the signing key. Mandates are signed here, in plain code,
only after the user approves the exact merchant-signed checkout.
"""

import json
import os
import time
import uuid

import httpx
import rfc8785
from ap2.sdk.generated.checkout_mandate import CheckoutMandate
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.mandate import MandateClient
from ap2.sdk.utils import b64url_decode, b64url_encode, compute_sha256_b64url
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from mcp import Client
from ucp_sdk.models.schemas.profile import BusinessSchema

UCP_VERSION = "2026-08-25"
AP2_CAPABILITY = "dev.ucp.common.payment.ap2_mandate"

# Where this platform publishes its UCP profile (merchants fetch our public key there).
PROFILE_URL = os.environ.get(
    "PLATFORM_PROFILE_URL", "http://127.0.0.1:8080/.well-known/ucp"
)
MERCHANT_URLS = [
    u.strip()
    for u in os.environ.get(
        "MERCHANT_URLS", "http://127.0.0.1:8081,http://127.0.0.1:8082"
    ).split(",")
    if u.strip()
]

# The platform's mandate-signing key. In production keep it in Secret Manager
# or a KMS/HSM; locally a fresh key is generated when the process starts.
if os.environ.get("PLATFORM_SIGNING_KEY"):
    KEY = JWK.from_json(os.environ["PLATFORM_SIGNING_KEY"])
else:
    KEY = JWK.generate(kty="EC", crv="P-256", kid="cineagent-1")

_merchants: dict[str, dict] = {}  # merchant URL -> discovered profile info


def platform_profile() -> dict:
    """This platform's UCP profile, served at PLATFORM_PROFILE_URL."""
    return {
        "ucp": {
            "version": UCP_VERSION,
            "capabilities": {
                "dev.ucp.shopping.checkout": [{"version": UCP_VERSION}],
                AP2_CAPABILITY: [
                    {"version": UCP_VERSION, "extends": "dev.ucp.shopping.checkout"}
                ],
            },
        },
        "keys": [json.loads(KEY.export_public())],
    }


async def discover(url: str) -> dict:
    """Fetch and validate a merchant's UCP profile from /.well-known/ucp."""
    async with httpx.AsyncClient(timeout=30) as http:
        resp = await http.get(f"{url}/.well-known/ucp")
        resp.raise_for_status()
    profile = BusinessSchema.model_validate(resp.json())
    capabilities = list(profile.ucp.capabilities or {})
    info = {
        "url": url,
        "mcp_endpoint": str(profile.ucp.services["dev.ucp.shopping"][0].endpoint),
        "capabilities": capabilities,
        "ap2_required": AP2_CAPABILITY in capabilities,
        "payment_handlers": [
            h.id for hs in profile.ucp.payment_handlers.values() for h in hs
        ],
        "keys": [k.model_dump(exclude_none=True) for k in profile.keys or []],
    }
    _merchants[url] = info
    return info


async def merchant(url: str) -> dict:
    return _merchants.get(url) or await discover(url)


async def call(url: str, tool: str, arguments: dict) -> dict:
    """Call a merchant's UCP tool over MCP. Every call carries our profile URL."""
    meta = {"ucp-agent": {"profile": PROFILE_URL}, "idempotency-key": str(uuid.uuid4())}
    async with Client((await merchant(url))["mcp_endpoint"]) as mcp:
        result = await mcp.call_tool(tool, {"meta": meta, **arguments})
    if result.is_error:
        raise RuntimeError(f"{tool} failed: {result.content}")
    return result.structured_content or {}


def step(text: str) -> str:
    """Print a protocol step in the agent's terminal and return it for the agent to show."""
    print(f"[platform] {text}", flush=True)
    return text


def short_error(e: BaseException) -> str:
    """One line for the model, e.g. '403 Forbidden' when Agent Gateway denies egress."""
    while isinstance(e, BaseExceptionGroup) and e.exceptions:
        e = e.exceptions[0]
    if isinstance(e, httpx.HTTPStatusError):
        return f"{e.response.status_code} {e.response.reason_phrase}: {e.response.text[:120]}"
    return f"{type(e).__name__}: {str(e)[:160]}"


def total(checkout: dict) -> int:
    return next(t["amount"] for t in checkout["totals"] if t["type"] == "total")


def verify_merchant_authorization(
    checkout: dict, merchant_keys: list[dict]
) -> str | None:
    """Check the merchant's signature (the price lock) on a checkout.

    Returns the merchant-signed checkout as a compact JWT, or None if the
    signature is missing or invalid.
    """
    detached = checkout.get("ap2", {}).get("merchant_authorization", "")
    if detached.count(".") != 2:
        return None
    header, _, signature = detached.split(".")
    payload = rfc8785.dumps({k: v for k, v in checkout.items() if k != "ap2"})
    checkout_jwt = f"{header}.{b64url_encode(payload)}.{signature}"
    kid = json.loads(b64url_decode(header)).get("kid")
    key = next((k for k in merchant_keys if k.get("kid") == kid), None)
    if not key:
        return None
    try:
        jws = JWS()
        jws.deserialize(checkout_jwt)
        jws.verify(JWK(**key))
    except Exception:  # noqa: BLE001
        return None
    return checkout_jwt


async def verified_checkout_jwt(url: str, checkout: dict) -> str | None:
    return verify_merchant_authorization(checkout, (await merchant(url))["keys"])


def sign_mandates(checkout: dict, checkout_jwt: str, payee: str) -> tuple[str, str]:
    """Sign the AP2 CheckoutMandate and PaymentMandate for exactly this checkout."""
    checkout_hash = compute_sha256_b64url(checkout_jwt)
    now = int(time.time())
    checkout_mandate = CheckoutMandate(
        checkout_jwt=checkout_jwt, checkout_hash=checkout_hash, iat=now, exp=now + 300
    )
    payment_mandate = PaymentMandate(
        transaction_id=checkout_hash,
        payee=Merchant(id=payee, name=payee),
        payment_amount=Amount(amount=total(checkout), currency=checkout["currency"]),
        payment_instrument=PaymentInstrument(
            id="instr_1", type="card", description="Demo card"
        ),
        iat=now,
        exp=now + 300,
    )
    client = MandateClient()
    return (
        client.create(payloads=[checkout_mandate], issuer_key=KEY),
        client.create(payloads=[payment_mandate], issuer_key=KEY),
    )


async def completion_request(
    checkout_id: str, url: str, checkout_mandate: str, payment_mandate: str
) -> dict:
    """complete_checkout arguments, with the mandates placed where UCP specifies."""
    handler_id = (await merchant(url))["payment_handlers"][0]
    return {
        "id": checkout_id,
        "checkout": {
            "payment": {
                "instruments": [
                    {
                        "id": "instr_1",
                        "handler_id": handler_id,
                        "type": "card",
                        "selected": True,
                        "credential": {
                            "type": "ap2_payment_mandate",
                            "token": payment_mandate,
                        },
                    }
                ]
            },
            "ap2": {"checkout_mandate": checkout_mandate},
        },
    }
