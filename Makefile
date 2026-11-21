# TypeSafe Guardrail Studio — container workflow.
#
#   make build   build the image
#   make run     start it on http://localhost:8080 (needs .env with TYPESAFE_API_KEY)
#   make stop    stop and remove the container
#   make logs    follow the container log
#   make restart stop + run
#   make status  is it up, and can it reach api.typesafe.ai?
#
#   make cloud        Cloud Run: enable APIs, put TYPESAFE_API_KEY in Secret Manager,
#                     build from source and deploy — prints the URL (needs gcloud + .env)
#   make cloud-url    print the service URL
#   make cloud-logs   tail the service log
#   make cloud-delete delete the service and the secret
#
#   PROJECT=my-gcp-project REGION=us-central1 make cloud   (PROJECT defaults to gcloud's)
#   PUBLIC=0 make cloud                                     (require IAM auth instead of public)

IMAGE     ?= jev-cvs
CONTAINER ?= jev-cvs
PORT      ?= 8080
ENV_FILE  ?= .env

# Cloud Run
SERVICE   ?= jev-cvs
REGION    ?= us-central1
PROJECT   ?= $(shell gcloud config get-value project 2>/dev/null)
SECRET    ?= typesafe-api-key
PUBLIC    ?= 1
AUTH_FLAG  = $(if $(filter 1,$(PUBLIC)),--allow-unauthenticated,--no-allow-unauthenticated)

.PHONY: build run stop logs restart status cloud cloud-url cloud-logs cloud-delete

build:
	docker build -t $(IMAGE) .

run: $(ENV_FILE)
	@docker rm -f $(CONTAINER) >/dev/null 2>&1 || true
	docker run -d --name $(CONTAINER) -p $(PORT):8080 --env-file $(ENV_FILE) $(IMAGE)
	@echo "TypeSafe Guardrail Studio → http://localhost:$(PORT)"

stop:
	@docker rm -f $(CONTAINER) >/dev/null 2>&1 && echo "stopped $(CONTAINER)" || echo "$(CONTAINER) was not running"

logs:
	docker logs -f $(CONTAINER)

restart: stop run

status:
	@docker ps --filter name=^/$(CONTAINER)$$ --format 'container: {{.Status}}' || true
	@curl -sf -m 5 http://localhost:$(PORT)/api/typesafe-status | head -c 200 || echo "api: not reachable on :$(PORT)"
	@echo

$(ENV_FILE):
	$(error $(ENV_FILE) not found — cp .env.example .env and set TYPESAFE_API_KEY)

# ---------------------------------------------------------------------------
# Cloud Run
# ---------------------------------------------------------------------------

cloud: $(ENV_FILE)
	@test -n "$(PROJECT)" || { echo "no GCP project: PROJECT=<id> make cloud, or gcloud config set project <id>"; exit 1; }
	@echo "project=$(PROJECT) region=$(REGION) service=$(SERVICE)"
	gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com --project $(PROJECT)
	@key=$$(grep -E '^TYPESAFE_API_KEY=' $(ENV_FILE) | head -1 | cut -d= -f2- | tr -d '"'); \
	  test -n "$$key" -a "$$key" != "MY_TYPESAFE_API_KEY" || { echo "TYPESAFE_API_KEY not set in $(ENV_FILE)"; exit 1; }; \
	  if gcloud secrets describe $(SECRET) --project $(PROJECT) >/dev/null 2>&1; then \
	    printf '%s' "$$key" | gcloud secrets versions add $(SECRET) --data-file=- --project $(PROJECT); \
	  else \
	    printf '%s' "$$key" | gcloud secrets create $(SECRET) --data-file=- --replication-policy=automatic --project $(PROJECT); \
	  fi
	@num=$$(gcloud projects describe $(PROJECT) --format='value(projectNumber)'); \
	  gcloud secrets add-iam-policy-binding $(SECRET) --project $(PROJECT) \
	    --member="serviceAccount:$$num-compute@developer.gserviceaccount.com" \
	    --role=roles/secretmanager.secretAccessor --quiet >/dev/null
	gcloud run deploy $(SERVICE) --source . --project $(PROJECT) --region $(REGION) --port 8080 \
	  --set-secrets TYPESAFE_API_KEY=$(SECRET):latest \
	  --set-env-vars NODE_ENV=development,DISABLE_HMR=true \
	  --cpu 1 --memory 1Gi --min-instances 0 --max-instances 3 --timeout 60 $(AUTH_FLAG)
	@$(MAKE) --no-print-directory cloud-url

cloud-url:
	@gcloud run services describe $(SERVICE) --project $(PROJECT) --region $(REGION) --format='value(status.url)'

cloud-logs:
	gcloud run services logs tail $(SERVICE) --project $(PROJECT) --region $(REGION)

cloud-delete:
	-gcloud run services delete $(SERVICE) --project $(PROJECT) --region $(REGION) --quiet
	-gcloud secrets delete $(SECRET) --project $(PROJECT) --quiet
