# Secure Agent Commerce with Gemini Enterprise

**Advent of Agents, Season 3, Day 16: the agent shops, only you can pay.**

A movie-booking agent that discovers merchants with the **Universal Commerce Protocol (UCP)** and pays with
**Agent Payments Protocol (AP2)** mandates. The agent can search and build a cart on its own, but money moves
only after you approve the exact merchant-signed cart, and the merchant verifies that approval cryptographically.

```
You ──"book 2 tickets"──▶ CineAgent (ADK) ──UCP over MCP──▶ Merchant
                              │  1. merchant signs the cart (ap2.merchant_authorization)
                              │  2. ADK pauses complete_purchase until you approve the amount
                              │  3. trusted platform code signs the AP2 Checkout + Payment Mandates
                              └──complete_checkout + mandates──▶ merchant verifies, issues tickets + signed receipt
```

## Run it (about 2 minutes)

You need [uv](https://docs.astral.sh/uv/), `git`, and `gcloud` with Application Default Credentials for a project that
has the Vertex AI API enabled.

```bash
git clone https://github.com/Sita04/secure-agent-commerce-gemini-enterprise.git
cd secure-agent-commerce-gemini-enterprise
gcloud auth application-default login
./setup.sh local YOUR_PROJECT_ID
```

Open http://localhost:8080, pick `cineagent`, and ask:

> Book 2 standard tickets for Oppenheimer at 9:30 PM at Meridian

The agent stops at an approval card for `complete_purchase(total_cents=3240)`. Approve it to get an order and a
signed receipt, or decline and nothing is paid.

## Try to cheat it

With `local` still running, open a second terminal:

```bash
./setup.sh test
```

| Attack | Merchant's answer |
|---|---|
| Replay mandates that were already used | `checkout_already_completed` |
| Pay $1 for a $47.52 cart | `mandate_scope_mismatch` |
| Reuse an approval on a different cart | `mandate_scope_mismatch` |
| Sign with a key from an unknown platform | `agent_missing_key` |
| Forge a key while claiming to be the trusted platform | `mandate_invalid_signature` |
| Submit an expired mandate | `mandate_expired` |
| Skip the approval and send no mandate | `mandate_required` |
| Approve one amount while the cart costs another | refused before signing |

## Deploy it behind Agent Gateway (about 25 minutes)

Before you start:

- A Google Cloud project with billing, inside an **organization** (Agent Identity principals are org-scoped),
  and Owner (or equivalent) permissions on it.
- `gcloud` with the alpha and beta components (`gcloud components install alpha beta`), plus `git` and `python3`.
- A region that supports semantic governance and has **no existing Agent Gateway** in your project
  (all Agent Runtime agents in one project and region bind to the same gateway). The default is `us-east1`;
  override it with `REGION=us-west1 ./setup.sh deploy ...`.
- Semantic governance policies are in Preview.

```bash
gcloud auth login && gcloud auth application-default login
./setup.sh deploy YOUR_PROJECT_ID     # REGION defaults to us-east1
./setup.sh chat YOUR_PROJECT_ID       # approve payments in your terminal
```

`deploy` creates:

| Piece | Where | Why |
|---|---|---|
| Meridian and StarLight merchants | Cloud Run, registered in Agent Registry | Public UCP merchants (MCP servers) |
| Platform UCP profile | Public Cloud Storage object | Merchants fetch the platform's public key here |
| Signing keys | Secret Manager | Merchant keys and the platform's mandate key |
| CineAgent | Agent Runtime, with Agent Identity, bound to the gateway | The agent; its egress goes through the gateway |
| Agent Gateway + IAP policy | `day16-egress` | Default-deny egress: Google APIs and **Meridian only** |
| Semantic governance policy | `ticket-spend-cap` | "Deny `complete_purchase` over $100" |

Then try:

- *"Book 2 standard tickets for Oppenheimer at 9:30 PM at Meridian, then pay."* The gateway lets it through,
  you approve in the terminal, and the merchant issues an order.
- *"What's playing at StarLight?"* The gateway blocks StarLight (`403`), so the agent reports it as unavailable.
- *"Buy 5 IMAX tickets for Oppenheimer at Meridian."* ($118.80) The semantic governance policy denies
  `complete_purchase` before you are even asked to approve.

The deployed agent keeps one Agent Runtime instance running, and the gateway and policy engine also bill
while they exist. `./setup.sh cleanup YOUR_PROJECT_ID` deletes what `deploy` created; it lists the few network
resources (VPC, DNS zone, network attachment, policy engine) to remove in the console afterwards.

## What's in the box

| File | Role |
|---|---|
| `merchant/main.py` | A UCP merchant as an MCP server: publishes `/.well-known/ucp`, signs every checkout, verifies mandates |
| `cineagent/agent.py` | The ADK agent and its four tools; `complete_purchase` requires your confirmation |
| `cineagent/trusted_platform.py` | Deterministic platform code: UCP calls, merchant-signature checks, AP2 mandate signing |
| `server.py` | ADK web UI and API, plus the platform's UCP profile (merchants fetch its public key here) |
| `attack_tests.py` | The attacks above |
| `deploy_agent.py` | Deploys the agent to Agent Runtime with Agent Identity and the gateway binding |
| `remote_chat.py` | Terminal chat for the deployed agent; payment approvals happen here |
| `setup.sh` | One script for everything |

## How it maps to the specs

- **Merchant authorization**: detached JWS (ES256) over the JCS-canonicalized checkout, in `ap2.merchant_authorization`
  ([UCP AP2 Mandates Extension](https://ucp.dev/2026-08-25/specification/payment/extensions/ap2-mandates/)).
- **User consent**: the "trusted platform provider" model. Mandates are signed with the platform's server key only after
  explicit consent from a deterministic channel (ADK tool confirmation), and the key is published in the platform's UCP
  profile. The AP2 specification requires the Trusted Surface to be non-agentic
  ([AP2 Specification](https://ap2-protocol.org/ap2/specification/)).
- **Mandates**: AP2 v0.2 Checkout Mandate and Payment Mandate as SD-JWTs, both bound to the hash of the merchant-signed
  checkout, created and verified with the official [AP2 Python SDK](https://github.com/google-agentic-commerce/AP2).

## Versions

UCP `2026-08-25` (`ucp-sdk` 0.5.0), AP2 v0.2.0 (pinned commit; the `ap2` package on PyPI is unrelated),
MCP Python SDK 2.3.0, ADK 2.11.0, `gemini-3.8-flash`.

## What's simplified

- Merchants keep checkouts in memory (one instance each). Locally they generate signing keys at startup; deployed,
  the keys come from Secret Manager.
- The platform's mandate-signing key is a Secret Manager secret exposed to the agent as an environment variable.
  In production, keep it in Cloud KMS or an HSM.
- The deployed agent keeps sessions in memory on a single instance, because ADK tool confirmation does not support
  the managed session service yet ([known limitation](https://adk.dev/tools-custom/confirmation/)).
- Egress rules use IAP policy V1 grants (`roles/iap.egressor` per Agent Registry entry), which work in organizations
  that block Unified Access Policy bindings. Unified Access Policies (V2) are the recommended model when available.
- The payment instrument is a placeholder; a real deployment routes the Payment Mandate to a credential provider.
- Merchant URLs are configured, not discovered from a registry.
