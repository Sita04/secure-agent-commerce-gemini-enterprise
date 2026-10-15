"""Try to cheat the merchants. Every attack must be rejected; the honest purchase must succeed.

This plays the role of a compromised or buggy agent platform talking straight to the merchant's
UCP tools (no LLM involved), so you can see exactly which check stops each attack. Watch the
terminal running `./setup.sh local` too: the merchant prints why it rejected each request.

Needs the merchants and the CineAgent server running (./setup.sh local does this).
Run:  ./setup.sh test
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

platform.step = lambda text: text  # keep this output focused on the attacks
MERCHANT = platform.MERCHANT_URLS[0]
results: list[tuple[str, bool]] = []


def code(result: dict) -> str:
    return (
        "completed"
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
    checkout_id: str, cm: str, pm: str, as_profile: str | None = None
) -> dict:
    args = await platform.completion_request(checkout_id, MERCHANT, cm, pm)
    old = platform.PROFILE_URL
    platform.PROFILE_URL = as_profile or old  # pretend to be a different platform
    try:
        return await platform.call(MERCHANT, "complete_checkout", args)
    finally:
        platform.PROFILE_URL = old


def report(n: int, title: str, attack: str, defense: str, want: str, got: str) -> None:
    ok = got.startswith(want)
    results.append((title, ok))
    print(f"\n[{n}/10] {title}")
    print(f"   Attack : {attack}")
    print(f"   Defense: {defense}")
    print(f"   Expect : {want}")
    print(f"   Got    : {got}   {'PASS' if ok else 'FAIL'}")


async def main() -> None:
    await platform.discover(MERCHANT)
    name = MERCHANT
    print(f"Attacking merchant {MERCHANT} (platform profile: {platform.PROFILE_URL})")

    c, jwt = await checkout("st_opp_930pm")
    cm, pm = platform.sign_mandates(c, jwt, name)
    report(
        1,
        "Honest purchase (the control case)",
        "None. Create a checkout, sign mandates for exactly that cart, submit them.",
        "-",
        "completed",
        code(await complete(c["id"], cm, pm)),
    )

    report(
        2,
        "Replay mandates that were already used",
        "Submit the same signed mandates again to buy a second time.",
        "The merchant marks a checkout completed; mandates are single use.",
        "checkout_already_completed",
        code(await complete(c["id"], cm, pm)),
    )

    c, jwt = await checkout("st_opp_7pm_imax")
    cheap = json.loads(json.dumps(c))
    cheap["totals"][-1]["amount"] = 100
    report(
        3,
        "Change the price on the agent side",
        "Edit the merchant's $47.52 checkout to say $1.00 before showing it to the user.",
        "The platform re-checks ap2.merchant_authorization; the edited cart no longer matches the signature.",
        "signature invalid",
        "signature invalid"
        if not platform.verify_merchant_authorization(
            cheap, (await platform.merchant(MERCHANT))["keys"]
        )
        else "signature accepted",
    )

    header, _, sig = jwt.split(".")
    forged_jwt = f"{header}.{b64url_encode(rfc8785.dumps({k: v for k, v in cheap.items() if k != 'ap2'}))}.{sig}"
    cm, pm = platform.sign_mandates(cheap, forged_jwt, name)
    report(
        4,
        "Pay $1 for a $47.52 cart",
        "Sign valid mandates for the edited $1.00 cart and submit them for the real checkout.",
        "The merchant checks the mandates point at the exact checkout (hash and amount) it signed.",
        "mandate_scope_mismatch",
        code(await complete(c["id"], cm, pm)),
    )

    small, small_jwt = await checkout("st_opp_930pm", qty=1)
    big, _ = await checkout("st_dune_8pm_imax", qty=4)
    cm, pm = platform.sign_mandates(small, small_jwt, name)
    report(
        5,
        "Reuse an approval on a different cart",
        "The user approved a $16.20 cart; submit those mandates to pay for a $95.04 cart instead.",
        "Mandates are bound to one checkout hash; the merchant compares it with the cart being paid.",
        "mandate_scope_mismatch",
        code(await complete(big["id"], cm, pm)),
    )

    c, jwt = await checkout("st_opp_930pm")
    rogue = JWK.generate(kty="EC", crv="P-256", kid="rogue")
    real_key, platform.KEY = platform.KEY, rogue
    cm, pm = platform.sign_mandates(c, jwt, name)
    platform.KEY = real_key
    report(
        6,
        "Unknown platform signs the mandates",
        "An attacker signs with its own key and points the merchant at its own UCP profile.",
        "The merchant only trusts platform profiles on its allow list (TRUSTED_PLATFORM_PROFILES).",
        "agent_missing_key",
        code(await complete(c["id"], cm, pm, "https://evil.example/.well-known/ucp")),
    )

    report(
        7,
        "Forged key, claiming to be the trusted platform",
        "Same attacker key, but now claiming to be CineAgent's trusted profile URL.",
        "The merchant fetches CineAgent's real public key from that profile; the signature does not verify.",
        "mandate_invalid_signature",
        code(await complete(c["id"], cm, pm)),
    )

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
    report(
        8,
        "Submit an old (expired) mandate",
        "Use a correctly signed Checkout Mandate that expired an hour ago.",
        "Mandates carry exp; the AP2 SDK rejects expired ones during verification.",
        "mandate_expired",
        code(await complete(c["id"], stale, pm)),
    )

    report(
        9,
        "Skip the approval entirely",
        "Call complete_checkout with no mandates, as an agent that bypassed the user would.",
        "The merchant requires ap2.checkout_mandate whenever AP2 is negotiated.",
        "mandate_required",
        code(
            await platform.call(
                MERCHANT, "complete_checkout", {"id": c["id"], "checkout": {}}
            )
        ),
    )

    from cineagent.agent import complete_purchase

    c, _ = await checkout("st_opp_7pm_imax")
    out = json.loads(await complete_purchase(c["id"], MERCHANT, total_cents=1500))
    report(
        10,
        "User approved $15.00, cart costs $47.52",
        "The model asks the user to approve a smaller amount than the merchant-signed total.",
        "complete_purchase compares the approved total_cents with the signed total before signing.",
        "approved amount does not match",
        out.get("error", "signed anyway"),
    )

    passed = sum(ok for _, ok in results)
    print(
        f"\n{passed}/{len(results)} checks behaved as expected: the honest purchase succeeded and every attack was stopped."
    )
    raise SystemExit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    asyncio.run(main())
