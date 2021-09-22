# See the file "COPYING" in the main distribution directory for copyright.

VERSION := $$(cat ../VERSION)

.PHONY: all

all:
	@docker build -t zeek:$(VERSION) -f Dockerfile ..
	@docker tag zeek:$(VERSION) zeek:latest

test:
	@TEST_TAG=zeek:$(VERSION) $(MAKE) -C btest
