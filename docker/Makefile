# See the file "COPYING" in the main distribution directory for copyright.

VERSION := $(shell cat ../VERSION)
LOCALVERSION ?=
LOCAL_VERSION_FLAG :=
ifneq ($(LOCALVERSION),)
	VERSION := $(VERSION)-$(LOCALVERSION)
	LOCAL_VERSION_FLAG := --localversion=$(LOCALVERSION)
endif

ZEEK_IMAGE ?= zeek:$(VERSION)

.PHONY: all test

all:
	docker build \
		--build-arg ZEEK_VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$$(git -C .. rev-parse HEAD) \
		--build-arg CREATED_DATE=$$(date -Iseconds) \
		--build-arg LOCAL_VERSION_FLAG=$(LOCAL_VERSION_FLAG) \
		-t $(ZEEK_IMAGE) \
		-f Dockerfile ..
	docker tag $(ZEEK_IMAGE) zeek:latest

test:
	@TEST_TAG=$(ZEEK_IMAGE) $(MAKE) -C btest
