#!/usr/bin/env bash
# Advent of Agents Day 16: the agent shops, only you can pay (UCP + AP2 + human approval).
#
#   ./setup.sh local PROJECT_ID     Run the merchants and the agent on your machine
#   ./setup.sh test                 Try to cheat the merchants (run while `local` is up)
#   ./setup.sh deploy PROJECT_ID    Deploy to Google Cloud behind Agent Gateway and policies (~25 min)
#   ./setup.sh chat PROJECT_ID      Chat with the deployed agent; approve payments in your terminal
#   ./setup.sh cleanup PROJECT_ID   Delete everything `deploy` created
set -euo pipefail
cd "$(dirname "$0")"

MODE="${1:-}"
PROJECT_ID="${2:-${GOOGLE_CLOUD_PROJECT:-}}"
REGION="${REGION:-us-east1}"   # any region that supports semantic governance and has no other Agent Gateway
STATE=.local
AP2_COMMIT=b4587ac1d055888a73b4b21750973cffba961793   # AP2 v0.2.0
AIP="google-cloud-aiplatform[agent_engines,adk]==2.5.0"
mkdir -p "$STATE"

# Local ports. Override with AGENT_PORT=9080 ./setup.sh local ... if 8080 is taken.
AGENT_PORT="${AGENT_PORT:-8080}"; MERIDIAN_PORT="${MERIDIAN_PORT:-8081}"; STARLIGHT_PORT="${STARLIGHT_PORT:-8082}"
local_env() {   # the agent and the merchants must agree on these URLs
  export PLATFORM_PROFILE_URL=http://127.0.0.1:$AGENT_PORT/.well-known/ucp
  export TRUSTED_PLATFORM_PROFILES=$PLATFORM_PROFILE_URL
  export MERCHANT_URLS=http://127.0.0.1:$MERIDIAN_PORT,http://127.0.0.1:$STARLIGHT_PORT
}

need() { command -v "$1" >/dev/null || { echo "Missing $1. Install it first ($2)."; exit 1; }; }
step() { echo; echo "==> $*"; }
need uv "https://docs.astral.sh/uv/"

new_key() {  # an EC P-256 signing key as a JWK, created once and reused
  [ -s "$STATE/$1.jwk" ] || uv run python -c \
    "from jwcrypto.jwk import JWK; print(JWK.generate(kty='EC', crv='P-256', kid='$1').export_private())" \
    > "$STATE/$1.jwk"
  cat "$STATE/$1.jwk"
}

cloud_vars() {
  [ -n "$PROJECT_ID" ] || { echo "Usage: ./setup.sh $MODE PROJECT_ID"; exit 1; }
  need gcloud "https://cloud.google.com/sdk/docs/install"
  export CLOUDSDK_CORE_PROJECT=$PROJECT_ID CLOUDSDK_BILLING_QUOTA_PROJECT=$PROJECT_ID GOOGLE_CLOUD_QUOTA_PROJECT=$PROJECT_ID
  N=$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')
  ORG=$(gcloud projects get-ancestors "$PROJECT_ID" --format='value(id,type)' | awk '$2=="organization"{print $1}')
  # Every Agent Runtime agent with Agent Identity in this project (see Day 5).
  AGENTS="principalSet://agents.global.org-$ORG.system.id.goog/attribute.platformContainer/aiplatform/projects/$N"
  MERIDIAN=https://day16-meridian-$N.$REGION.run.app
  STARLIGHT=https://day16-starlight-$N.$REGION.run.app
  PROFILE_BUCKET=$PROJECT_ID-day16-platform
  PROFILE_URL=https://storage.googleapis.com/$PROFILE_BUCKET/.well-known/ucp
  GW=day16-egress
}

agent_name() {
  uv run --with "$AIP" python -c "
import vertexai
c = vertexai.Client(project='$PROJECT_ID', location='$REGION')
print(next((a.api_resource.name for a in c.agent_engines.list() if a.api_resource.display_name == 'day16-cineagent'), ''))" 2>/dev/null
}

case "$MODE" in
local)
  [ -n "$PROJECT_ID" ] || { echo "Usage: ./setup.sh local PROJECT_ID"; exit 1; }
  uv sync -q
  local_env
  cat > cineagent/.env <<EOF
GOOGLE_CLOUD_PROJECT=$PROJECT_ID
GOOGLE_CLOUD_LOCATION=global
GOOGLE_GENAI_USE_ENTERPRISE=True
EOF
  export PLATFORM_SIGNING_KEY="$(new_key cineagent-1)"
  trap 'kill $(jobs -p) 2>/dev/null' EXIT
  THEATER=meridian PORT=$MERIDIAN_PORT uv run python merchant/main.py &
  THEATER=starlight PORT=$STARLIGHT_PORT uv run python merchant/main.py &
  echo
  echo "Merchants: http://127.0.0.1:$MERIDIAN_PORT/.well-known/ucp  http://127.0.0.1:$STARLIGHT_PORT/.well-known/ucp"
  echo "Agent:     http://127.0.0.1:$AGENT_PORT  (pick 'cineagent', then ask: Book 2 standard tickets for Oppenheimer at 9:30 PM at Meridian)"
  echo "Attacks:   in another terminal run ./setup.sh test"
  echo
  PORT=$AGENT_PORT uv run python server.py
  ;;

test)
  local_env
  PLATFORM_SIGNING_KEY="$(cat "$STATE/cineagent-1.jwk")" uv run python attack_tests.py
  ;;

deploy)
  cloud_vars
  uv sync -q

  step "1/7 Enable APIs"
  gcloud services enable aiplatform.googleapis.com run.googleapis.com cloudbuild.googleapis.com \
    artifactregistry.googleapis.com secretmanager.googleapis.com agentregistry.googleapis.com apphub.googleapis.com \
    networkservices.googleapis.com networksecurity.googleapis.com iap.googleapis.com compute.googleapis.com \
    dns.googleapis.com logging.googleapis.com cloudresourcemanager.googleapis.com storage.googleapis.com

  step "2/7 Signing keys in Secret Manager, platform UCP profile on a public URL"
  for k in meridian starlight platform; do
    kid=$k-1; [ $k = platform ] && kid=cineagent-1
    new_key $kid >/dev/null
    gcloud secrets describe day16-$k-key >/dev/null 2>&1 || \
      gcloud secrets create day16-$k-key --replication-policy=automatic --data-file="$STATE/$kid.jwk" -q
  done
  PLATFORM_SIGNING_KEY="$(cat $STATE/cineagent-1.jwk)" uv run python -c \
    "import json; from cineagent.trusted_platform import platform_profile; print(json.dumps(platform_profile()))" \
    > "$STATE/platform-profile.json"
  gcloud storage buckets describe gs://$PROFILE_BUCKET >/dev/null 2>&1 || \
    gcloud storage buckets create gs://$PROFILE_BUCKET --location=$REGION --uniform-bucket-level-access -q
  gcloud storage cp "$STATE/platform-profile.json" gs://$PROFILE_BUCKET/.well-known/ucp \
    --content-type=application/json --cache-control=no-store -q
  gcloud storage buckets add-iam-policy-binding gs://$PROFILE_BUCKET --member=allUsers --role=roles/storage.objectViewer -q >/dev/null

  step "3/7 Merchants on Cloud Run as MCP servers, registered in Agent Registry with their URL and tools"
  SA=day16-merchant@$PROJECT_ID.iam.gserviceaccount.com
  gcloud iam service-accounts describe $SA >/dev/null 2>&1 || \
    { gcloud iam service-accounts create day16-merchant --display-name="Day 16 UCP merchants" -q; sleep 10; }
  for m in meridian starlight; do
    gcloud secrets add-iam-policy-binding day16-$m-key --member=serviceAccount:$SA \
      --role=roles/secretmanager.secretAccessor -q >/dev/null
    gcloud run deploy day16-$m --source=merchant --region=$REGION \
      --allow-unauthenticated --max-instances=1 --service-account=$SA \
      --set-env-vars="THEATER=$m,PUBLIC_URL=https://day16-$m-$N.$REGION.run.app,TRUSTED_PLATFORM_PROFILES=$PROFILE_URL" \
      --set-secrets="MERCHANT_SIGNING_KEY=day16-$m-key:latest" -q
  done
  # Agent Gateway matches traffic by URL, so register each merchant with its URL and tool list.
  uv run python -c "
import asyncio, json
from mcp import Client
async def main():
    async with Client('$MERIDIAN/mcp') as c:
        tools = (await c.list_tools()).tools
    print(json.dumps({'tools': [{'name': t.name, 'description': t.description, 'inputSchema': t.input_schema} for t in tools]}))
asyncio.run(main())" > "$STATE/toolspec.json"
  for m in meridian starlight; do
    gcloud alpha agent-registry services describe day16-$m-mcp --location=$REGION >/dev/null 2>&1 || \
      gcloud alpha agent-registry services create day16-$m-mcp --location=$REGION --display-name="day16-$m UCP merchant" \
        --interfaces="url=https://day16-$m-$N.$REGION.run.app,protocolBinding=jsonrpc" \
        --mcp-server-spec-type=tool-spec --mcp-server-spec-content="$STATE/toolspec.json" -q
  done

  step "4/7 Agent Gateway (egress) with IAP authorization"
  gcloud compute networks describe day16-net >/dev/null 2>&1 || gcloud compute networks create day16-net --subnet-mode=custom -q
  gcloud compute networks subnets describe day16-subnet --region=$REGION >/dev/null 2>&1 || \
    gcloud compute networks subnets create day16-subnet --network=day16-net --region=$REGION --range=10.20.0.0/24 \
      --enable-private-ip-google-access -q
  gcloud dns managed-zones describe day16-zone >/dev/null 2>&1 || \
    gcloud dns managed-zones create day16-zone --dns-name=day16.internal. --visibility=private --networks=day16-net \
      --description="Day 16: semantic governance endpoint" -q
  gcloud compute network-attachments describe day16-attach --region=$REGION >/dev/null 2>&1 || \
    gcloud compute network-attachments create day16-attach --region=$REGION --subnets=day16-subnet \
      --connection-preference=ACCEPT_AUTOMATIC -q
  # VPC connectivity can only be set when the gateway is created; semantic governance needs it (DNS peering).
  cat > "$STATE/template.yaml" <<EOF
name: projects/$N/locations/$REGION/agentConnectivityTemplates/day16-template
accessPath: AGENT_TO_ANYWHERE
deploymentModel: CENTRALIZED
egressNetworkConfig:
  networkAttachment: projects/$PROJECT_ID/regions/$REGION/networkAttachments/day16-attach
  dnsPeeringConfig:
    domain: day16.internal.
    targetNetwork: projects/$PROJECT_ID/global/networks/day16-net
  vpcEgress: PRIVATE_RANGES_ONLY
EOF
  cat > "$STATE/gateway.yaml" <<EOF
name: $GW
protocols: [MCP]
googleManaged:
  governedAccessPath: AGENT_TO_ANYWHERE
agentConnectivityTemplate: projects/$N/locations/$REGION/agentConnectivityTemplates/day16-template
registries:
  - //agentregistry.googleapis.com/projects/$PROJECT_ID/locations/$REGION
EOF
  cat > "$STATE/iap-ext.yaml" <<EOF
name: day16-iap-ext
service: iap.googleapis.com
failOpen: false
timeout: 1s
metadata:
  iapPolicyVersion: "V1"
EOF
  cat > "$STATE/iap-policy.yaml" <<EOF
name: day16-iap-policy
target:
  resources: ["projects/$PROJECT_ID/locations/$REGION/agentGateways/$GW"]
policyProfile: REQUEST_AUTHZ
action: CUSTOM
customProvider:
  authzExtension:
    resources: ["projects/$PROJECT_ID/locations/$REGION/authzExtensions/day16-iap-ext"]
EOF
  gcloud network-services agent-connectivity-templates describe day16-template --location=$REGION >/dev/null 2>&1 || \
    gcloud network-services agent-connectivity-templates import day16-template --source="$STATE/template.yaml" --location=$REGION -q
  gcloud network-services agent-gateways describe $GW --location=$REGION >/dev/null 2>&1 || \
    gcloud network-services agent-gateways import $GW --source="$STATE/gateway.yaml" --location=$REGION -q
  gcloud beta service-extensions authz-extensions import day16-iap-ext --source="$STATE/iap-ext.yaml" --location=$REGION -q >/dev/null
  gcloud network-security authz-policies import day16-iap-policy --source="$STATE/iap-policy.yaml" --location=$REGION -q >/dev/null

  step "5/7 Egress allow list: Google APIs the agent needs, plus ONLY the approved merchant"
  for h in aiplatform us-east1-aiplatform agentregistry $REGION-agentregistry cloudresourcemanager logging monitoring \
           cloudtrace telemetry oauth2 iamcredentials sts; do
    h=${h/us-east1/$REGION}
    for v in "" ".mtls"; do
      host=$h$v.googleapis.com; id=day16-$(echo $h$v | tr . -)
      gcloud alpha agent-registry services describe $id --location=$REGION >/dev/null 2>&1 || \
        gcloud alpha agent-registry services create $id --location=$REGION --display-name=$host \
          --endpoint-spec-type=no-spec --interfaces="url=https://$host,protocolBinding=jsonrpc" -q >/dev/null
    done
  done
  for id in $(gcloud agent-registry endpoints list --location=$REGION --filter='displayName~googleapis.com' --format='value(name.basename())'); do
    gcloud beta iap web add-iam-policy-binding --resource-type=agent-registry --endpoint=$id --region=$REGION \
      --member="$AGENTS" --role=roles/iap.egressor --condition=None -q >/dev/null
  done
  APPROVED=$(gcloud agent-registry mcp-servers list --location=$REGION --filter="interfaces.url=$MERIDIAN" --format='value(name.basename())')
  gcloud beta iap web add-iam-policy-binding --resource-type=agent-registry --mcp-server=$APPROVED --region=$REGION \
    --member="$AGENTS" --role=roles/iap.egressor --condition=None -q >/dev/null
  echo "Allowed: Meridian ($MERIDIAN). StarLight gets no grant, so the gateway blocks it."

  step "6/7 Agent on Agent Runtime with Agent Identity, bound to the gateway"
  for role in roles/aiplatform.user roles/serviceusage.serviceUsageConsumer roles/browser roles/agentregistry.viewer \
              roles/logging.logWriter roles/monitoring.metricWriter; do
    gcloud projects add-iam-policy-binding $PROJECT_ID --member="$AGENTS" --role=$role --condition=None -q >/dev/null
  done
  gcloud secrets add-iam-policy-binding day16-platform-key --member="$AGENTS" --role=roles/secretmanager.secretAccessor -q >/dev/null
  gcloud secrets add-iam-policy-binding day16-platform-key --role=roles/secretmanager.secretAccessor -q \
    --member=serviceAccount:service-$N@gcp-sa-aiplatform-re.iam.gserviceaccount.com >/dev/null 2>&1 || true
  gcloud storage buckets describe gs://$PROJECT_ID-day16-staging >/dev/null 2>&1 || \
    gcloud storage buckets create gs://$PROJECT_ID-day16-staging --location=$REGION --uniform-bucket-level-access -q
  if [ ! -s $STATE/ap2-0.1-py3-none-any.whl ]; then   # AP2 is not on PyPI; build the pinned release
    rm -rf $STATE/ap2-src && git clone -q https://github.com/google-agentic-commerce/AP2.git $STATE/ap2-src
    git -C $STATE/ap2-src checkout -q $AP2_COMMIT && uv build --wheel -q -o $STATE $STATE/ap2-src
  fi
  export PROJECT_ID REGION GATEWAY=$GW STAGING_BUCKET=$PROJECT_ID-day16-staging AP2_WHEEL=$STATE/ap2-0.1-py3-none-any.whl \
    MERCHANT_URLS=$MERIDIAN,$STARLIGHT PLATFORM_PROFILE_URL=$PROFILE_URL PLATFORM_KEY_SECRET=day16-platform-key
  OLD=$(agent_name)   # re-runs replace the agent; create is the reliable path for secret-backed env vars
  [ -n "$OLD" ] && uv run --with "$AIP" python -c \
    "import vertexai; vertexai.Client(project='$PROJECT_ID', location='$REGION').agent_engines.delete(name='$OLD', force=True)"
  uv run --with "$AIP" python deploy_agent.py | tail -1 | tee "$STATE/agent-name"

  step "7/7 Semantic governance policy: deny purchases over \$100"
  gcloud beta services identity create --service=aiplatform.googleapis.com -q >/dev/null 2>&1
  for role in roles/compute.networkAdmin roles/dns.admin; do
    gcloud projects add-iam-policy-binding $PROJECT_ID --role=$role --condition=None -q >/dev/null \
      --member=serviceAccount:service-$N@gcp-sa-aiplatform.iam.gserviceaccount.com
  done
  engine() { gcloud beta ai semantic-governance-policy-engine describe --location=$REGION --project=$PROJECT_ID --format=json 2>/dev/null; }
  engine | grep -q '"state": "ACTIVE"' || gcloud beta ai semantic-governance-policy-engine update --location=$REGION --project=$PROJECT_ID -q \
    --gateway-config="name=$GW,network=projects/$PROJECT_ID/global/networks/day16-net,subnetwork=projects/$PROJECT_ID/regions/$REGION/subnetworks/day16-subnet,dns-zone-name=day16-zone" >/dev/null
  until engine | python3 -c "import json,sys; e=json.load(sys.stdin); sys.exit(e.get('gatewayConfigs',{}).get('$GW',{}).get('state')!='ACTIVE')"; do
    echo "   waiting for the policy engine (2-20 minutes)..."; sleep 30
  done
  SGP_HOST=$(engine | python3 -c "import json,sys; print(json.load(sys.stdin)['gatewayConfigs']['$GW']['dnsRecord'].rstrip('.'))")
  cat > "$STATE/sgp-ext.yaml" <<EOF
name: day16-sgp-ext
service: $SGP_HOST
authority: $SGP_HOST
failOpen: false
timeout: 10s
loadBalancingScheme: LOAD_BALANCING_SCHEME_UNSPECIFIED
EOF
  cat > "$STATE/sgp-policy.yaml" <<EOF
name: day16-sgp-policy
target:
  loadBalancingScheme: LOAD_BALANCING_SCHEME_UNSPECIFIED
  resources: [projects/$PROJECT_ID/locations/$REGION/agentGateways/$GW]
httpRules:
- to:
    operations:
    - paths:
      - prefix: /
  when: "!request.headers['content-type'].startsWith('application/grpc') && (request.path.endsWith(':generateContent') || request.path.endsWith(':streamGenerateContent'))"
action: CUSTOM
policyProfile: CONTENT_AUTHZ
customProvider:
  authzExtension:
    resources: [projects/$PROJECT_ID/locations/$REGION/authzExtensions/day16-sgp-ext]
EOF
  gcloud service-extensions authz-extensions import day16-sgp-ext --source="$STATE/sgp-ext.yaml" --location=$REGION -q >/dev/null
  gcloud network-security authz-policies import day16-sgp-policy --source="$STATE/sgp-policy.yaml" --location=$REGION -q >/dev/null
  REG_AGENT=$(gcloud agent-registry agents list --location=$REGION --filter='displayName=day16-cineagent' --format='value(name)')
  gcloud beta ai semantic-governance-policies delete ticket-spend-cap --location=$REGION --project=$PROJECT_ID -q >/dev/null 2>&1 || true
  gcloud beta ai semantic-governance-policies create ticket-spend-cap --location=$REGION --project=$PROJECT_ID --agent="$REG_AGENT" \
      --display-name="Ticket spend cap \$100" \
      --natural-language-constraint='Deny any call to the complete_purchase tool where total_cents is greater than 10000, because purchases over $100.00 need a human outside this agent.'

  echo
  echo "Deployed: $(cat $STATE/agent-name)"
  echo "Try it:   ./setup.sh chat $PROJECT_ID"
  ;;

chat)
  cloud_vars
  uv run --with "$AIP" python remote_chat.py "$(agent_name)"
  ;;

cleanup)
  cloud_vars
  NAME=$(agent_name)
  [ -n "$NAME" ] && uv run --with "$AIP" python -c \
    "import vertexai; vertexai.Client(project='$PROJECT_ID', location='$REGION').agent_engines.delete(name='$NAME', force=True)"
  gcloud beta ai semantic-governance-policies delete ticket-spend-cap --location=$REGION --project=$PROJECT_ID -q || true
  gcloud network-security authz-policies delete day16-sgp-policy --location=$REGION -q || true
  gcloud network-security authz-policies delete day16-iap-policy --location=$REGION -q || true
  gcloud service-extensions authz-extensions delete day16-sgp-ext --location=$REGION -q || true
  gcloud service-extensions authz-extensions delete day16-iap-ext --location=$REGION -q || true
  gcloud network-services agent-gateways delete $GW --location=$REGION -q || true
  gcloud network-services agent-connectivity-templates delete day16-template --location=$REGION -q || true
  for s in $(gcloud alpha agent-registry services list --location=$REGION --filter='name~day16-' --format='value(name.basename())'); do
    gcloud alpha agent-registry services delete $s --location=$REGION -q || true
  done
  gcloud run services delete day16-meridian --region=$REGION -q || true
  gcloud run services delete day16-starlight --region=$REGION -q || true
  for s in meridian starlight platform; do gcloud secrets delete day16-$s-key -q || true; done
  gcloud storage rm -r gs://$PROFILE_BUCKET gs://$PROJECT_ID-day16-staging -q || true
  gcloud iam service-accounts delete day16-merchant@$PROJECT_ID.iam.gserviceaccount.com -q || true
  echo "The semantic governance engine, network attachment, DNS zone and day16-net VPC are left in place;"
  echo "delete them in the console once the gateway deletion has finished."
  ;;

*)
  sed -n '2,9p' "$0"
  exit 1
  ;;
esac
