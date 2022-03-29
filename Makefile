PROJECT_VERSION := 0.0.3
DOCKER_REPO     := synfinatic
PROJECT_NAME    := netflow2ng

DIST_DIR ?= dist/
GOOS ?= $(shell uname -s | tr "[:upper:]" "[:lower:]")
ARCH ?= $(shell uname -m)
ifeq ($(ARCH),x86_64)
GOARCH             := amd64
else
GOARCH             := $(ARCH)  # no idea if this works for other platforms....
endif

PROJECT_TAG               := $(shell git describe --tags 2>/dev/null $(git rev-list --tags --max-count=1))
PROJECT_COMMIT            := $(shell git rev-parse HEAD || echo "")
PROJECT_DELTA             := $(shell DELTA_LINES=$$(git diff | wc -l); if [ $${DELTA_LINES} -ne 0 ]; then echo $${DELTA_LINES} ; else echo "''" ; fi)

BUILDINFOSDET ?=
PROGRAM_ARGS ?=
ifeq ($(PROJECT_TAG),)
PROJECT_TAG               := NO-TAG
endif
ifeq ($(PROJECT_COMMIT),)
PROJECT_COMMIT            := NO-CommitID
endif
ifeq ($(PROJECT_DELTA),)
PROJECT_DELTA             :=
endif
VERSION_PKG               := $(shell echo $(PROJECT_VERSION) | sed 's/^v//g')
LICENSE                   := MIT
URL                       := https://github.com/$(DOCKER_REPO)/$(PROJECT_NAME)
DESCRIPTION               := NetFlow2ng: a NetFlow v9 collector for ntopng
BUILDINFOS                := $(shell date +%FT%T%z)$(BUILDINFOSDET)
HOSTNAME                  := $(shell hostname)
LDFLAGS                   := -X "main.Version=$(PROJECT_VERSION)" -X "main.Delta=$(PROJECT_DELTA)" -X "main.Buildinfos=$(BUILDINFOS)" -X "main.Tag=$(PROJECT_TAG)" -X "main.CommitID=$(PROJECT_COMMIT)"
OUTPUT_NAME               ?= $(DIST_DIR)$(PROJECT_NAME)-$(PROJECT_VERSION)  # default for current platform

ALL: netflow2ng

include help.mk

test: vet unittest lint ## Run important tests

precheck: test test-fmt test-tidy ## Run all tests that happen in a PR

clean:
	rm -rf dist

clean-docker:
	docker-compose -f docker-compose-pkg.yml rm -f
	docker image rm netflow2ng_packager:v$(PROJECT_VERSION)
	docker image rm $(DOCKER_REPO)/$(PROJECT_NAME):v$(PROJECT_VERSION)

clean-go:
	go clean -i -r -cache -modcache

netflow2ng: $(OUTPUT_NAME)

$(OUTPUT_NAME): prepare
	go build -ldflags='$(LDFLAGS)' -o $(OUTPUT_NAME) ./cmd/...

PHONY: docker-run
docker-run:  ## Run docker container locally
	docker run -it --rm \
		-p 5556:5556/tcp \
		-p 8080:8080/tcp \
		-p 2055:2055/udp \
		$(DOCKER_REPO)/$(PROJECT_NAME):v$(PROJECT_VERSION)

PHONY: docker
docker:  ## Build docker image
	docker build -t $(DOCKER_REPO)/$(PROJECT_NAME):v$(PROJECT_VERSION) .

docker-release: ## Tag and push docker images Linux AMD64
	docker build \
		-t $(DOCKER_REPO)/$(PROJECT_NAME):v$(PROJECT_VERSION) \
		-t $(DOCKER_REPO)/$(PROJECT_NAME):latest \
		--build-arg VERSION=v$(PROJECT_VERSION) \
		-f Dockerfile .
	docker push $(DOCKER_REPO)/$(PROJECT_NAME):v$(PROJECT_VERSION)
	docker push $(DOCKER_REPO)/$(PROJECT_NAME):latest

.PHONY: unittest
unittest: ## Run go unit tests
	go test -race -covermode=atomic -coverprofile=coverage.out  ./...

.PHONY: vet
vet:  # Go vet
	@echo checking code is vetted...
	go vet $(shell go list ./...)

.PHONY: test-race
test-race:
	@echo testing code for races...
	go test -race ./...

.PHONY: fmt
fmt: ## Format Go code
	@go fmt cmd

.PHONY: test-fmt
test-fmt: fmt ## Test to make sure code if formatted correctly
	@if test `git diff cmd | wc -l` -gt 0; then \
	    echo "Code changes detected when running 'go fmt':" ; \
	    git diff -Xfiles ; \
	    exit -1 ; \
	fi

.PHONY: test-tidy
test-tidy:  ## Test to make sure go.mod is tidy
	@go mod tidy
	@if test `git diff go.mod | wc -l` -gt 0; then \
	    echo "Need to run 'go mod tidy' to clean up go.mod" ; \
	    exit -1 ; \
	fi

lint:  ## Run golangci-lint
	golangci-lint run

.PHONY: prepare
prepare:
	mkdir -p $(DIST_DIR)

.PHONY: package
package:  ## Build .deb and .rpm packages
	docker-compose -f docker-compose-pkg.yml up

# These targets aren't for you.
.PHONY: .package-deb
.package-deb: $(OUTPUT_NAME)
	fpm -s dir -t deb -n $(PROJECT_NAME) -v $(PROJECT_VERSION) \
        --description "$(DESCRIPTION)"  \
        --url "$(URL)" \
        --architecture $(ARCH) \
        --license "$(LICENSE)" \
       	--deb-no-default-config-files \
        --package $(DIST_DIR) \
        $(OUTPUT_NAME)=/usr/bin/netflow2ng \
        package/netflow2ng.service=/lib/systemd/system/netflow2ng.service \
        package/netflow2ng.env=/etc/default/netflow2ng

.PHONY: .package-rpm
.package-rpm: $(OUTPUT_NAME)
	fpm -s dir -t rpm -n $(PROJECT_NAME) -v $(PROJECT_VERSION) \
        --description "$(DESCRIPTION)" \
        --url "$(URL)" \
        --architecture $(ARCH) \
        --license "$(LICENSE) "\
        --package $(DIST_DIR) \
        $(OUTPUT_NAME)=/usr/bin/netflow2ng \
        package/netflow2ng.service=/lib/systemd/system/netflow2ng.service \
        package/netflow2ng.env=/etc/default/netflow2ng
