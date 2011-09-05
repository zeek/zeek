#
# A simple static wrapper for a number of standard Makefile targets,
# mostly just forwarding to build/Makefile. This is provided only for
# convenience and supports only a subset of what CMake's Makefile
# to offer. For more, execute that one directly. 
#

BUILD=build

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
	@./pkg/make-src-packages

bindist:
	@( cd pkg && ( ./make-deb-packages || ./make-mac-packages || \
	               ./make-rpm-packages ) )

distclean:
	rm -rf $(BUILD)

configured:
	@test -d $(BUILD) || ( echo "Error: No build/ directory found. Did you run configure?" && exit 1 )
	@test -e $(BUILD)/Makefile || ( echo "Error: No build/Makefile found. Did you run configure?" && exit 1 )

.PHONY : all install clean doc docclean dist bindist distclean configured
