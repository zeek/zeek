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

dist: configured
	( cd $(BUILD) && make package_source )

distclean:
	rm -rf $(BUILD)

.PHONY : configured
configured:
	@test -d $(BUILD) || ( echo "Error: No build/ directory found. Did you run configure?" && exit 1 )
	@test -e $(BUILD)/Makefile || ( echo "Error: No build/Makefile found. Did you run configure?" && exit 1 )
