# Cedar (cedar-go) ext_authz demo for agentgateway — local k3d (no registry)
IMG     ?= cedar-authz:local      # local tag, imported into k3d (never pushed)
CLUSTER ?= agw-demo
NS      ?= agentgateway-system

.PHONY: tidy build image k3d-import load secret keycloak gateway deploy undeploy logs port-forward gw-forward kc-forward redeploy

tidy:
	cd cedar-authz-server && go mod tidy

build: tidy
	cd cedar-authz-server && CGO_ENABLED=0 go build -o /dev/null .

# Build the image for the cluster's arch (k3d nodes match your host arch — no --platform needed).
image:
	docker build -t $(IMG) cedar-authz-server

# Load the locally-built image into the k3d cluster (replaces a registry push).
k3d-import:
	k3d image import $(IMG) -c $(CLUSTER)

# build + import in one step
load: image k3d-import

# Create the OpenAI provider secret from $OPENAI_API_KEY (key field MUST be 'Authorization').
secret:
	@test -n "$$OPENAI_API_KEY" || { echo "set OPENAI_API_KEY first"; exit 1; }
	kubectl create secret generic openai-secret -n $(NS) \
	  --from-literal=Authorization="$$OPENAI_API_KEY" \
	  --dry-run=client -o yaml | kubectl apply -f -

# Deploy Keycloak (the demo IdP) + import the cedar-demo realm. The realm's hardcoded
# protocol mappers stamp the team/tier/org/scp claims that Cedar authorizes on.
keycloak:
	kubectl create namespace keycloak 2>/dev/null || true
	kubectl create configmap keycloak-realm -n keycloak \
	  --from-file=realm-cedar-demo.json=keycloak/realm-cedar-demo.json \
	  --dry-run=client -o yaml | kubectl apply -f -
	kubectl apply -f keycloak/keycloak.yaml
	kubectl rollout status -n keycloak deploy/keycloak --timeout=180s

# Create the data-plane Gateway (controller provisions the proxy Deployment + Service).
gateway:
	kubectl apply -f k8s/05-gateway.yaml

# Apply gateway + cedar service + routes + both extAuth policies. Deployment pulls nothing
# (imagePullPolicy: Never) — it uses the image imported by `make load`.
# Prereq: `make secret` (needs $OPENAI_API_KEY) so the OpenAI backend can authenticate.
deploy: gateway secret
	kubectl apply -f k8s/00-namespace.yaml
	kubectl apply -f k8s/10-cedar-authz-deploy.yaml
	kubectl set image -n $(NS) deploy/cedar-authz-server cedar-authz-server=$(IMG)
	# Apply routes only if the cluster doesn't already provide them:
	kubectl apply -f k8s/20-openai-backend-route.yaml || true
	kubectl apply -f k8s/40-mcp-backend-route.yaml || true
	kubectl apply -f k8s/30-policy-openai-extauth.yaml
	kubectl apply -f k8s/50-policy-mcp-extauth.yaml
	kubectl rollout status -n $(NS) deploy/cedar-authz-server

# Rebuild, reimport, and restart the pod after a code/policy change.
redeploy: load
	kubectl rollout restart -n $(NS) deploy/cedar-authz-server
	kubectl rollout status  -n $(NS) deploy/cedar-authz-server

undeploy:
	kubectl delete -f k8s/50-policy-mcp-extauth.yaml --ignore-not-found
	kubectl delete -f k8s/30-policy-openai-extauth.yaml --ignore-not-found
	kubectl delete -f k8s/10-cedar-authz-deploy.yaml --ignore-not-found

logs:
	kubectl logs -n $(NS) deploy/cedar-authz-server -f

port-forward:
	kubectl port-forward -n $(NS) svc/cedar-authz-server 9090:9090

# Port-forward the gateway itself (send real OpenAI requests to localhost:8080).
gw-forward:
	kubectl port-forward -n $(NS) svc/agentgateway 8080:80

# Port-forward Keycloak on 8081 (the token script's default KEYCLOAK_URL).
kc-forward:
	kubectl port-forward -n keycloak svc/keycloak 8081:8080
