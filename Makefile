# Jev guardrail demo. Needs TYPESAFE_API_KEY in the environment or in .env
-include .env
export TYPESAFE_API_KEY
PORT ?= 3100
IMAGE ?= jev-guardrail

.PHONY: build run dev test stop

build:            ## build the Docker image
	docker build -t $(IMAGE) docker

run: build        ## run the Docker image on $(PORT)
	docker run --rm -p $(PORT):3000 -e TYPESAFE_API_KEY=$(TYPESAFE_API_KEY) $(IMAGE)

dev:              ## test mode, no Docker: plain node, same server
	PORT=$(PORT) node docker/server.js

test:             ## live accuracy run against a running server (make dev or make run first)
	node docker/test.mjs http://localhost:$(PORT)

stop:
	-docker ps -q --filter ancestor=$(IMAGE) | xargs -r docker stop
