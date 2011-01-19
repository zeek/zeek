#
# A simple static wrapper for a number of standard Makefile targets,
# mostly just forwarding to build/Makefile. This is provided only for
# convenience and supports only a subset of what CMake's Makefile
# to offer. For more, execute that one directly. 
#

BUILD=build
BROCCOLI=aux/broccoli
BROCTL=aux/broctl

# CMake/CPack versions before 2.8.2 have bugs that can create bad packages
CMAKE_PACK_REQ=2.8.2
CMAKE_VER=`cmake -version`

OSX_VER_CMD=sw_vers | sed -n 's/ProductVersion://p' | cut -d . -f 2

all: configured
	( cd $(BUILD) && make )

install: configured
	( cd $(BUILD) && make install )

clean: configured
	( cd $(BUILD) && make clean )

dist: cmake_version
	# Minimum Bro source package
	( \
	./configure --ignore-dirs='aux/broctl;aux/broccoli' --pkg-name-prefix=Bro && \
	cd $(BUILD) && \
	make package_source \
	)
	# Full Bro source package
	( \
	./configure --pkg-name-prefix=Bro-all && \
	cd $(BUILD) && \
	make package_source \
	)
	# Broccoli source package
	( \
	cd $(BROCCOLI) && \
	./configure && \
	cd $(BUILD) && \
	make package_source && \
	mv Broccoli*.tar.gz ../../../$(BUILD)/ && \
	cd .. && \
	rm -r $(BUILD) \
	)
	# Broctl source package
	( \
	cd $(BROCTL) && \
	./configure && \
	cd $(BUILD) && \
	make package_source && \
	mv Broctl*.tar.gz ../../../$(BUILD)/ && \
	cd .. && \
	rm -r $(BUILD) \
	)

distclean:
	rm -rf $(BUILD)

configured:
	@test -d $(BUILD) || ( echo "Error: No build/ directory found. Did you run configure?" && exit 1 )
	@test -e $(BUILD)/Makefile || ( echo "Error: No build/Makefile found. Did you run configure?" && exit 1 )

cmake_version:
	@test "$(CMAKE_VER)" \> "cmake version $(CMAKE_PACK_REQ)" || ( echo "Error: please use a CMake version greater than $(CMAKE_PACK_REQ)" && exit 1 )

.PHONY : all install clean distclean configured cmake_version
