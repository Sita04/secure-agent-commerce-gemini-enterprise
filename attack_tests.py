"""Try to cheat the merchants. Every attack must be rejected; the honest purchase must succeed.

Needs the merchants and the CineAgent server running (./setup.sh local does this).
Run:  python attack_tests.py
"""

import asyncio
import json
import time

import rfc8785

from ap2.sdk.generated.checkout_mandate import CheckoutMandate
from ap2.sdk.mandate import MandateClient
from ap2.sdk.utils import b64url_encode
from jwcrypto.jwk import JWK

from cineagent import trusted_platform as platform

MERCHANT = platform.MERCHANT_URLS[0]
rows: list[tuple[str, str, bool]] = []


def code(result: dict) -> str:
    return (
        result.get("status")
        if result.get("status") == "completed"
        else result["messages"][0]["code"]
    )


async def checkout(showtime: str, qty: int = 2) -> tuple[dict, str]:
    c = await platform.call(
        MERCHANT,
        "create_checkout",
        {"checkout": {"line_items": [{"item": {"id": showtime}, "quantity": qty}]}},
    )
    jwt = platform.verify_merchant_authorization(
        c, (await platform.merchant(MERCHANT))["keys"]
    )
    assert jwt, "merchant signature must verify"
    return c, jwt


async def complete(
    checkout_id: str, cm: str, pm: str, meta_profile: str | None = None
) -> dict:
    args = await platform.completion_request(checkout_id, MERCHANT, cm, pm)
    if meta_profile:  # pretend to be a different platform
        old, platform.PROFILE_URL = platform.PROFILE_URL, meta_profile
        try:
            return await platform.call(MERCHANT, "complete_checkout", args)
        finally:
            platform.PROFILE_URL = old
    return await platform.call(MERCHANT, "complete_checkout", args)


def check(name: str, got: str, want: str) -> None:
    rows.append((name, got, got == want))


async def main() -> None:
    await platform.discover(MERCHANT)
    name = MERCHANT

    # 1. Honest purchase: merchant-signed checkout, user-approved mandates.
    c, jwt = await checkout("st_opp_930pm")
    cm, pm = platform.sign_mandates(c, jwt, name)
    check("Honest purchase", code(await complete(c["id"], cm, pm)), "completed")

    # 2. Replay the same mandates.
    check(
        "Replay used mandates",
        code(await complete(c["id"], cm, pm)),
        "checkout_already_completed",
    )

    # 3. Tamper with the price, then sign mandates for the cheaper cart.
    c, jwt = await checkout("st_opp_7pm_imax")
    cheap = json.loads(json.dumps(c))
    cheap["totals"][-1]["amount"] = 100
    check(
        "Platform spots tampered price",
        str(
            platform.verify_merchant_authorization(
                cheap, (await platform.merchant(MERCHANT))["keys"]
            )
        ),
        "None",
    )
    header, _, sig = jwt.split(".")

    forged_jwt = f"{header}.{b64url_encode(rfc8785.dumps({k: v for k, v in cheap.items() if k != 'ap2'}))}.{sig}"
    cm, pm = platform.sign_mandates(cheap, forged_jwt, name)
    check(
        "Pay $1 for a $47.52 cart",
        code(await complete(c["id"], cm, pm)),
        "mandate_scope_mismatch",
    )

    # 4. Approve a cheap cart, submit the approval against an expensive one.
    small, small_jwt = await checkout("st_opp_930pm", qty=1)
    big, _ = await checkout("st_dune_8pm_imax", qty=4)
    cm, pm = platform.sign_mandates(small, small_jwt, name)
    check(
        "Reuse approval on another cart",
        code(await complete(big["id"], cm, pm)),
        "mandate_scope_mismatch",
    )

    # 5. An unknown platform signs with its own key.
    c, jwt = await checkout("st_opp_930pm")
    rogue = JWK.generate(kty="EC", crv="P-256", kid="rogue")
    old_key, platform.KEY = platform.KEY, rogue
    cm, pm = platform.sign_mandates(c, jwt, name)
    platform.KEY = old_key
    check(
        "Untrusted platform profile",
        code(await complete(c["id"], cm, pm, "https://evil.example/.well-known/ucp")),
        "agent_missing_key",
    )

    # 6. Same rogue key, but claiming to be the trusted platform.
    check(
        "Forged key, trusted profile URL",
        code(await complete(c["id"], cm, pm)),
        "mandate_invalid_signature",
    )

    # 7. Expired mandate.
    past = int(time.time()) - 3600
    stale = MandateClient().create(
        payloads=[
            CheckoutMandate(
                checkout_jwt=jwt,
                checkout_hash=platform.compute_sha256_b64url(jwt),
                iat=past - 300,
                exp=past,
            )
        ],
        issuer_key=platform.KEY,
    )
    _, pm = platform.sign_mandates(c, jwt, name)
    check(
        "Expired mandate", code(await complete(c["id"], stale, pm)), "mandate_expired"
    )

    # 8. No mandate at all (an agent that skips the approval step).
    check(
        "No mandate (skipped approval)",
        code(
            await platform.call(
                MERCHANT, "complete_checkout", {"id": c["id"], "checkout": {}}
            )
        ),
        "mandate_required",
    )

    # 9. The user approved $15.00 but the cart costs more: the tool refuses to sign.
    from cineagent.agent import complete_purchase

    c, _ = await checkout("st_opp_7pm_imax")
    out = json.loads(await complete_purchase(c["id"], MERCHANT, total_cents=1500))
    check(
        "Approved amount != signed total",
        out.get("error", "signed")[:22],
        "approved amount does n",
    )

    width = max(len(r[0]) for r in rows)
    for name_, got, ok in rows:
        print(f"{'PASS' if ok else 'FAIL'}  {name_:<{width}}  -> {got}")
    print(f"\n{sum(r[2] for r in rows)}/{len(rows)} checks passed")
    raise SystemExit(0 if all(r[2] for r in rows) else 1)


if __name__ == "__main__":
    asyncio.run(main())
