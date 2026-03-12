REGISTRY ?= 192.168.1.200:5000/archlabs
TAG ?= v1.8

CLIENT_IMAGE ?= $(REGISTRY)/blockchain-client
SERVER_IMAGE ?= $(REGISTRY)/blockchain-server

PLATFORM_AMD ?= linux/amd64
PLATFORM_ARM ?= linux/arm64
KUBECTL ?= kubectl
KUBECTL_APPLY_FLAGS ?= --validate=false
NAMESPACE ?= blockchain-system
K8S_APPLY_FILES := \
	k8s/namespace.yaml \
	client/k8s/deployment.yaml \
	client/k8s/service.yaml \
	client/k8s/ingress.yaml \
	server/k8s/deployment.yaml \
	server/k8s/service.yaml
K8S_DELETE_FILES := \
	k8s/namespace.yaml

build-client:
	docker build -t blockchain-client:local ./client

build-server:
	docker build -t blockchain-server:local ./server

build: build-client build-server

push-client:
	docker tag blockchain-client:local $(CLIENT_IMAGE):$(TAG)
	docker push $(CLIENT_IMAGE):$(TAG)

push-server:
	docker tag blockchain-server:local $(SERVER_IMAGE):$(TAG)
	docker push $(SERVER_IMAGE):$(TAG)

push: push-client push-server

push-client-amd:
	docker buildx build --platform $(PLATFORM_AMD) -t $(CLIENT_IMAGE):$(TAG)-amd64 --push ./client

push-client-arm:
	docker buildx build --platform $(PLATFORM_ARM) -t $(CLIENT_IMAGE):$(TAG)-arm64 --push ./client

push-server-amd:
	docker buildx build --platform $(PLATFORM_AMD) -t $(SERVER_IMAGE):$(TAG)-amd64 --push ./server

push-server-arm:
	docker buildx build --platform $(PLATFORM_ARM) -t $(SERVER_IMAGE):$(TAG)-arm64 --push ./server

k8s-deploy:
	@for file in $(K8S_APPLY_FILES); do \
		$(KUBECTL) apply $(KUBECTL_APPLY_FLAGS) -f $$file; \
	done

k8s-delete:
	@for file in $(K8S_DELETE_FILES); do \
		$(KUBECTL) delete -f $$file --ignore-not-found; \
	done

.PHONY: \
	build build-client build-server \
	push push-client push-server \
	push-client-amd push-client-arm push-server-amd push-server-arm \
	k8s-deploy k8s-delete
