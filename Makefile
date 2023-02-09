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

doc:
	$(MAKE) -C doc $@

docclean:
	(cd doc && make clean)

livehtml:
	$(MAKE) -C doc $@

# The COPYFILE_DISABLE flag used in the tar commands below is an undocumented feature
# of the tar binary on macOS. It causes tar to avoid including any of the special files
# that macOS litters around the repository directory, such as ._ resource files, none
# of which should be included in the distribution packages.
dist:
	@test -e ../$(VERSION_FULL) && rm -ri ../$(VERSION_FULL) || true
	@cp -R . ../$(VERSION_FULL)
	@for i in . $$(git submodule foreach -q --recursive realpath --relative-to=$$(pwd) .); do ((cd ../$(VERSION_FULL)/$$i && test -f .git && cp -R $(GITDIR) .gitnew && rm -f .git && mv .gitnew .git && sed -i.bak -e 's#[[:space:]]*worktree[[:space:]]*=[[:space:]]*.*##g' .git/config) || true); done
	@for i in . $$(git submodule foreach -q --recursive realpath --relative-to=$$(pwd) .); do (cd ../$(VERSION_FULL)/$$i && git reset -q --hard && git clean -ffdxq); done
	@(cd ../$(VERSION_FULL) && find . -name \.git\* | xargs rm -rf)
	@(cd ../$(VERSION_FULL) && find . -name \.idea -type d | xargs rm -rf)
	@(cd ../$(VERSION_FULL) && find . -maxdepth 1 -name build\* | xargs rm -rf)
	@python3 ./ci/collect-repo-info.py --only-git > ../$(VERSION_FULL)/repo-info.json
	@mv ../$(VERSION_FULL) .
	@COPYFILE_DISABLE=true tar -czf $(VERSION_FULL).tar.gz $(VERSION_FULL)
	@echo Package: $(VERSION_FULL).tar.gz
	@mv $(VERSION_FULL) $(VERSION_MIN)
	@(cd $(VERSION_MIN) && for i in auxil/*; do rm -rf $$i/*; done)
	@COPYFILE_DISABLE=true tar -czf $(VERSION_MIN).tar.gz $(VERSION_MIN)
	@echo Package: $(VERSION_MIN).tar.gz
	@rm -rf $(VERSION_MIN)

distclean:
	rm -rf $(BUILD)
	$(MAKE) -C testing $@

test:
	-@( cd testing && make )

test-aux:
	-test -d auxil/zeekctl && ( cd auxil/zeekctl && make test-all )
	-test -d auxil/btest  && ( cd auxil/btest && make test )
	-test -d auxil/zeek-aux && ( cd auxil/zeek-aux && make test )
	-test -d auxil/plugins && ( cd auxil/plugins && make test-all )

test-all: test test-aux

configured:
	@test -d $(BUILD) || ( echo "Error: No build/ directory found. Did you run configure?" && exit 1 )
	@test -e $(BUILD)/Makefile || ( echo "Error: No build/Makefile found. Did you run configure?" && exit 1 )

.PHONY : all install clean doc docclean dist distclean configured livehtml
