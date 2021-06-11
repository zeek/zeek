
include(ZeekSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

set(session_SRCS
  Session.cc
  Key.cc
  Manager.cc
)

bro_add_subdir_library(session ${session_SRCS})
add_dependencies(bro_session generate_outputs)
