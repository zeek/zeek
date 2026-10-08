# See the file "COPYING" in the main distribution directory for copyright.

VERSION := $(shell python3 ../auxil/zeek-aux/devel-tools/get-version.py --source ..)
ZEEK_IMAGE ?= zeek:$(VERSION)

.PHONY: all test

all:
	docker build \
		--build-arg ZEEK_VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$$(git -C .. rev-parse HEAD) \
		--build-arg CREATED_DATE=$$(date -Iseconds) \
		-t $(ZEEK_IMAGE) \
		-f Dockerfile ..
	docker tag $(ZEEK_IMAGE) zeek:latest

test:
	@TEST_TAG=$(ZEEK_IMAGE) $(MAKE) -C btest
