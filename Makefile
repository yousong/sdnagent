BINDIR:=_output/bin

GO_BUILD_FLAGS:=-mod vendor
GO_BUILD:=go build $(GO_BUILD_FLAGS)
GO_TEST:=go test $(GO_BUILD_FLAGS)
export GO111MODULE:=on

sdnagent:=$(BINDIR)/sdnagent
bins:= \
	$(sdnagent) \

all: $(bins)

$(bins): | $(BINDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

$(sdnagent):
	$(GO_BUILD) -o $(BINDIR)/$(notdir $@) yunion.io/x/sdnagent/cmd/$(notdir $@)

mod:
	GOPROXY=direct go get -v yunion.io/x/onecloud@master
	GOPROXY=direct go mod vendor -v

.PHONY: mod

test:
	$(GO_TEST)  -v ./...

rpm: $(bins)
	$(CURDIR)/build/build.sh sdnagent

REGISTRY ?= registry.cn-beijing.aliyuncs.com/yunionio
VERSION ?= $(shell git describe --exact-match 2> /dev/null || \
	   git describe --match=$(git rev-parse --short=8 HEAD) --always --dirty --abbrev=8)
IMAGE_NAME_TAG := $(REGISTRY)/sdnagent:$(VERSION)

DOCKER_ALPINE_BUILD_IMAGE:=registry.cn-beijing.aliyuncs.com/yunionio/alpine-build:1.0-2
docker-alpine-build:
	docker run --rm \
		--name "docker-alpine-build-onecloud-sdnagent" \
		-v $(CURDIR):/root/go/src/yunion.io/x/sdnagent \
		-v $(CURDIR)/_output/alpine-build:/root/go/src/yunion.io/x/sdnagent/_output \
		$(DOCKER_ALPINE_BUILD_IMAGE) \
		/bin/sh -c "set -ex; cd /root/go/src/yunion.io/x/sdnagent; make $(F); chown -R $$(id -u):$$(id -g) _output"

docker-alpine-build-stop:
	docker stop --time 0 docker-alpine-build-onecloud-sdnagent || true
.PHONY: docker-alpine-build
.PHONY: docker-alpine-build-stop

docker-image:
	DEBUG=${DEBUG} REGISTRY=${REGISTRY} TAG=${VERSION} ARCH=${ARCH} ${CURDIR}/scripts/docker_push.sh

docker-image-push:
	PUSH=true DEBUG=${DEBUG} REGISTRY=${REGISTRY} TAG=${VERSION} ARCH=${ARCH} ${CURDIR}/scripts/docker_push.sh

.PHONY: docker-image
.PHONY: docker-image-push

.PHONY: all $(bins) rpm test
