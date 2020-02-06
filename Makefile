EXTENSION ?=
DIST_DIR ?= dist/
GOOS ?= $(shell uname -s | tr "[:upper:]" "[:lower:]")
ARCH ?= $(shell uname -m)
BUILDINFOSDET ?=

DOCKER_REPO        := synfinatic/
NETFLOW2NG_NAME    := netflow2ng
NETFLOW2NG_VERSION := $(shell git describe --tags 2>/dev/null $(git rev-list --tags --max-count=1))
VERSION_PKG        := $(shell echo $(NETFLOW2NG_NAME) | sed 's/^v//g')
ARCH               := x86_64
LICENSE            := MIT
URL                := https://github.com/synfinatic/netflow2ng
DESCRIPTION        := NetFlow2ng: an NetFlow v9 collector to ntopng
BUILDINFOS         := ($(shell date +%FT%T%z)$(BUILDINFOSDET))
LDFLAGS            := '-X main.version=$(NETFLOW2NG_VERSION) -X main.buildinfos=$(BUILDINFOS)'

OUTPUT_NETFLOW2NG  := $(DIST_DIR)netflow2ng-$(NETFLOW2NG_VERSION)-$(GOOS)-$(ARCH)$(EXTENSION)

ALL: test-race vet test netflow2ng

clean:
	rm -rf dist

netflow2ng: $(OUTPUT_NETFLOW2NG)

$(OUTPUT_NETFLOW2NG): prepare
	go build -ldflags $(LDFLAGS) -o $(OUTPUT_NETFLOW2NG) cmd/netflow2ng/netflow2ng.go

.PHONY: test
test:
	@echo testing code
	go test ./...

.PHONY: vet
vet:
	@echo checking code is vetted
	go vet $(shell go list ./...)

.PHONY: test-race
test-race:
	@echo testing code for races
	go test -race ./...

.PHONY: prepare
prepare:
	mkdir -p $(DIST_DIR)

.PHONY: package-deb-goflow
package-deb-goflow: $(OUTPUT_NETFLOW2NG)
	fpm -s dir -t deb -n $(NETFLOW2NG_NAME) -v $(VERSION_PKG) \
        --description "$(DESCRIPTION)"  \
        --url "$(URL)" \
        --architecture $(ARCH) \
        --license "$(LICENSE)" \
       	--deb-no-default-config-files \
        --package $(DIST_DIR) \
        $(OUTPUT_NETFLOW2NG)=/usr/bin/netflow2ng \
        package/netflow2ng.service=/lib/systemd/system/netflow2ng.service \
        package/netflow2ng.env=/etc/default/netflow2ng

.PHONY: package-rpm-netflow2ng
package-rpm-netflow2ng: $(OUTPUT_NETFLOW2NG)
	fpm -s dir -t rpm -n $(NETFLOW2NG_NAME) -v $(VERSION_PKG) \
        --description "$(DESCRIPTION)" \
        --url "$(URL)" \
        --architecture $(ARCH) \
        --license "$(LICENSE) "\
        --package $(DIST_DIR) \
        $(OUTPUT_NETFLOW2NG)=/usr/bin/netflow2ng \
        package/netflow2ng.service=/lib/systemd/system/netflow2ng.service \
        package/netflow2ng.env=/etc/default/netflow2ng
