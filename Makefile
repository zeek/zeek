#
# A simple static wrapper for a number of standard Makefile targets,
# mostly just forwarding to build/Makefile. This is provided only for
# convenience and supports only a subset of what CMake's Makefile
# offers. For more, execute that one directly. 
#

BUILD=build
REPO=$$(cd $(CURDIR) && basename $$(git config --get remote.origin.url | sed 's/^[^:]*://g'))
VERSION_FULL=$(REPO)-$$(cd $(CURDIR) && cat VERSION)
VERSION_MIN=$(REPO)-$$(cd $(CURDIR) && cat VERSION)-minimal
GITDIR=$$(test -f .git && echo $$(cut -d" " -f2 .git) || echo .git)

all: configured
	$(MAKE) -C $(BUILD) $@

install: configured all
	$(MAKE) -C $(BUILD) $@

install-aux: configured
	$(MAKE) -C $(BUILD) $@

clean: configured docclean
	$(MAKE) -C $(BUILD) $@

doc: configured
	$(MAKE) -C $(BUILD) $@

docclean: configured
	$(MAKE) -C $(BUILD) $@

dist:
	@test -e ../$(VERSION_FULL) && rm -ri ../$(VERSION_FULL) || true
	@cp -R . ../$(VERSION_FULL)
	@for i in . $$(git submodule foreach -q --recursive realpath --relative-to=$$(pwd) .); do ((cd ../$(VERSION_FULL)/$$i && test -f .git && cp -R $(GITDIR) .gitnew && rm -f .git && mv .gitnew .git && sed -i.bak -e 's#[[:space:]]*worktree[[:space:]]*=[[:space:]]*.*##g' .git/config) || true); done
	@for i in . $$(git submodule foreach -q --recursive realpath --relative-to=$$(pwd) .); do (cd ../$(VERSION_FULL)/$$i && git reset -q --hard && git clean -ffdxq); done
	@(cd ../$(VERSION_FULL) && find . -name \.git\* | xargs rm -rf)
	@mv ../$(VERSION_FULL) .
	@tar -czf $(VERSION_FULL).tar.gz $(VERSION_FULL)
	@echo Package: $(VERSION_FULL).tar.gz
	@mv $(VERSION_FULL) $(VERSION_MIN)
	@(cd $(VERSION_MIN) && for i in aux/*; do rm -rf $$i/*; done)
	@tar -czf $(VERSION_MIN).tar.gz $(VERSION_MIN)
	@echo Package: $(VERSION_MIN).tar.gz
	@rm -rf $(VERSION_MIN)

distclean:
	rm -rf $(BUILD)
	$(MAKE) -C testing $@

test:
	-@( cd testing && make )

test-aux:
	-test -d aux/broctl && ( cd aux/broctl && make test-all )
	-test -d aux/btest  && ( cd aux/btest && make test )
	-test -d aux/bro-aux && ( cd aux/bro-aux && make test )
	-test -d aux/plugins && ( cd aux/plugins && make test-all )

test-all: test test-aux

configured:
	@test -d $(BUILD) || ( echo "Error: No build/ directory found. Did you run configure?" && exit 1 )
	@test -e $(BUILD)/Makefile || ( echo "Error: No build/Makefile found. Did you run configure?" && exit 1 )

.PHONY : all install clean doc docclean dist distclean configured
