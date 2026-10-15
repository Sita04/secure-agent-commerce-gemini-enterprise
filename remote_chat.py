"""Chat with the deployed CineAgent on Agent Runtime. Payment approvals happen here, in your terminal.

Usage:  python remote_chat.py REASONING_ENGINE_NAME [message ...]
With messages, runs them in order and approves every payment (for scripted tests).
"""

import asyncio
import json
import sys

import vertexai

NAME, SCRIPT = sys.argv[1], sys.argv[2:]
location = NAME.split("/")[3]
client = vertexai.Client(project=NAME.split("/")[1], location=location)
agent = client.agent_engines.get(name=NAME)


async def send(session_id: str, message) -> dict | None:
    """Stream one turn. Returns a pending adk_request_confirmation call, if any."""
    pending = None
    async for event in agent.async_stream_query(
        user_id="learner", session_id=session_id, message=message
    ):
        for part in (event.get("content") or {}).get("parts", []):
            if part.get("text") and not part.get("thought"):
                print(f"\nagent: {part['text'].strip()}")
            call = part.get("function_call")
            if call and call["name"] == "adk_request_confirmation":
                pending = call
            elif call:
                print(f"  -> {call['name']}({json.dumps(call.get('args', {}))})")
            resp = part.get("function_response")
            if resp and resp["name"] != "adk_request_confirmation":
                print(
                    f"  <- {resp['name']}: {json.dumps(resp.get('response', {}))[:300]}"
                )
        if event.get("error_message"):
            print(f"  !! {event.get('error_code')}: {event['error_message']}")
    return pending


async def main() -> None:
    session = await agent.async_create_session(user_id="learner")
    messages = iter(SCRIPT) if SCRIPT else None
    while True:
        text = next(messages, None) if messages else input("\nyou: ").strip()
        if not text:
            break
        pending = await send(session["id"], text)
        while pending:
            original = pending["args"]["originalFunctionCall"]
            print(
                f"\nAPPROVAL REQUIRED: {original['name']}({json.dumps(original['args'])})"
            )
            ok = (
                True
                if messages
                else input("Approve this payment? [y/N] ").strip().lower() == "y"
            )
            print("approved" if ok else "declined")
            pending = await send(
                session["id"],
                {
                    "role": "user",
                    "parts": [
                        {
                            "function_response": {
                                "id": pending["id"],
                                "name": "adk_request_confirmation",
                                "response": {"confirmed": ok},
                            }
                        }
                    ],
                },
            )


asyncio.run(main())
