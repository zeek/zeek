#
# A simple static wrapper for a number of standard Makefile targets,
# mostly just forwarding to build/Makefile. This is provided only for
# convenience and supports only a subset of what CMake's Makefile
# to offer. For more, execute that one directly. 
#

SOURCE=$(PWD)
BUILD=$(SOURCE)/build
TMP=/tmp/bro-dist.$(UID)
BRO_V=`cat $(SOURCE)/VERSION`
BROCCOLI_V=`cat $(SOURCE)/aux/broccoli/VERSION`
BROCTL_V=`cat $(SOURCE)/aux/broctl/VERSION`

all: configured
	( cd $(BUILD) && make )

install: configured
	( cd $(BUILD) && make install )

clean: configured
	( cd $(BUILD) && make clean )
	( cd $(BUILD) && make docclean && make restclean )

doc: configured
	( cd $(BUILD) && make doc )

docclean: configured
	( cd $(BUILD) && make docclean && make restclean )

dist:
	@( mkdir -p $(BUILD) && rm -rf $(TMP) && mkdir $(TMP) )
	@cp -R $(SOURCE) $(TMP)/Bro-$(BRO_V)
	@( cd $(TMP) && find . -name .git\* | xargs rm -rf )
	@( cd $(TMP) && find . -name \*.swp | xargs rm -rf )
	@( cd $(TMP) && find . -type d -name build | xargs rm -rf )
	@( cd $(TMP) && tar -czf $(BUILD)/Bro-all-$(BRO_V).tar.gz Bro-$(BRO_V) )
	@( cd $(TMP)/Bro-$(BRO_V)/aux && mv broccoli Broccoli-$(BROCCOLI_V) && \
	    tar -czf $(BUILD)/Broccoli-$(BROCCOLI_V).tar.gz Broccoli-$(BROCCOLI_V) )
	@( cd $(TMP)/Bro-$(BRO_V)/aux && mv broctl Broctl-$(BROCTL_V) && \
	    tar -czf $(BUILD)/Broctl-$(BROCTL_V).tar.gz Broctl-$(BROCTL_V) )
	@( cd $(TMP)/Bro-$(BRO_V)/aux && rm -rf Broctl* Broccoli* )
	@( cd $(TMP) && tar -czf $(BUILD)/Bro-$(BRO_V).tar.gz Bro-$(BRO_V) )
	@rm -rf $(TMP)
	@echo "Distribution source tarballs have been compiled in $(BUILD)"

bindist:
	@( cd pkg && ( ./make-deb-packages || ./make-mac-packages || \
	               ./make-rpm-packages ) )

distclean:
	rm -rf $(BUILD)

configured:
	@test -d $(BUILD) || ( echo "Error: No build/ directory found. Did you run configure?" && exit 1 )
	@test -e $(BUILD)/Makefile || ( echo "Error: No build/Makefile found. Did you run configure?" && exit 1 )

.PHONY : all install clean doc docclean dist bindist distclean configured
