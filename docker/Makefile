# See the file "COPYING" in the main distribution directory for copyright.

VERSION := $(shell cat ../VERSION)
LOCALVERSION ?= ""
LOCAL_VERSION_FLAG = ""
ifneq ($(LOCALVERSION), "")
	VERSION := $(VERSION)-$(LOCALVERSION)
	LOCAL_VERSION_FLAG := --localversion=$(LOCALVERSION)
endif
BUILD_IMAGE := zeek-builder:$(VERSION)
BUILD_CONTAINER := zeek-builder-container-$(VERSION)
ZEEK_IMAGE ?= zeek:$(VERSION)
BUILD_DIR ?= build-docker
ZEEK_CONFIGURE_FLAGS ?= \
	--build-dir=$(BUILD_DIR) \
	--generator=Ninja \
	--build-type=Release \
	--disable-btest-pcaps \
	--disable-broker-tests \
	--disable-cpp-tests $(LOCAL_VERSION_FLAG)

.PHONY: all

all:
	-docker rm $(BUILD_CONTAINER)
	docker build -t $(BUILD_IMAGE) -f builder.Dockerfile .
	docker run --name $(BUILD_CONTAINER) \
		-v $(CURDIR)/../:/src/zeek -w /src/zeek \
		$(BUILD_IMAGE) bash -xeu -c "./configure $(ZEEK_CONFIGURE_FLAGS) && ninja -C $(BUILD_DIR) install"
	docker commit $(BUILD_CONTAINER) zeek-build
	docker build -t $(ZEEK_IMAGE) -f final.Dockerfile .
	docker tag $(ZEEK_IMAGE) zeek:latest

test:
	@TEST_TAG=zeek:$(VERSION) $(MAKE) -C btest
