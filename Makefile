#
# A simple static wrapper for a number of standard Makefile targets,
# mostly just forwarding to build/Makefile. This is provided only for
# convenience and supports only a subset of what CMake's Makefile
# offers. For more, execute that one directly. 
#

BUILD=build
REPO=`basename \`git config --get remote.origin.url | sed 's/^[^:]*://g'\``
VERSION_FULL=$(REPO)-`cat VERSION`
VERSION_MIN=$(REPO)-`cat VERSION`-minimal
HAVE_MODULES=git submodule | grep -v cmake >/dev/null

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
	@rm -rf $(VERSION_FULL) $(VERSION_FULL).tgz
	@rm -rf $(VERSION_MIN) $(VERSION_MIN).tgz
	@git clone --recursive . $(VERSION_FULL) >/dev/null 2>&1
	@find $(VERSION_FULL) -name .git\* | xargs rm -rf
	@tar -czf $(VERSION_FULL).tgz $(VERSION_FULL) && echo Package: $(VERSION_FULL).tgz && rm -rf $(VERSION_FULL)
	@$(HAVE_MODULES) && git clone . $(VERSION_MIN) >/dev/null 2>&1 || exit 0
	@$(HAVE_MODULES) && (cd $(VERSION_MIN) && git submodule update --init cmake >/dev/null 2>&1) || exit 0
	@$(HAVE_MODULES) && (cd $(VERSION_MIN) && git submodule update --init src/3rdparty >/dev/null 2>&1) || exit 0
	@$(HAVE_MODULES) && (cd $(VERSION_MIN) && git submodule update --init magic >/dev/null 2>&1) || exit 0
	@$(HAVE_MODULES) && find $(VERSION_MIN) -name .git\* | xargs rm -rf || exit 0
	@$(HAVE_MODULES) && tar -czf $(VERSION_MIN).tgz $(VERSION_MIN) && echo Package: $(VERSION_MIN).tgz && rm -rf $(VERSION_MIN) || exit 0

bindist:
	@( cd pkg && ( ./make-deb-packages || ./make-mac-packages || \
	               ./make-rpm-packages ) )

distclean:
	rm -rf $(BUILD)

test:
	@( cd testing && make )

test-all: test
	test -d aux/broctl && ( cd aux/broctl && make test )
	test -d aux/btest  && ( cd aux/btest && make test )

configured:
	@test -d $(BUILD) || ( echo "Error: No build/ directory found. Did you run configure?" && exit 1 )
	@test -e $(BUILD)/Makefile || ( echo "Error: No build/Makefile found. Did you run configure?" && exit 1 )

.PHONY : all install clean doc docclean dist bindist distclean configured
