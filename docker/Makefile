# See the file "COPYING" in the main distribution directory for copyright.

VERSION := $$(cat ../VERSION)

.PHONY: all

all:
	@docker build -t zeek:$(VERSION) -f Dockerfile ..
