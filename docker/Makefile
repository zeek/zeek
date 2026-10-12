# See the file "COPYING" in the main distribution directory for copyright.

PYTHON ?= python3
VERSION := $(shell $(PYTHON) ../tools/scripts/get-version.py --source ..)
ifndef VERSION
$(error Could not determine Zeek version; set PYTHON to a working Python 3 interpreter)
endif
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
