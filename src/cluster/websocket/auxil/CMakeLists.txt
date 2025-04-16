option(IXWEBSOCKET_INSTALL "Install IXWebSocket" OFF)

set(BUILD_SHARED_LIBS OFF)
set(USE_TLS ON)
set(USE_OPEN_SSL ON)

add_subdirectory(IXWebSocket)

# We are not interested in any warnings from `IXWebSocket`'s compilation
# itself, suppress them.
target_compile_options(ixwebsocket PRIVATE "-w")
