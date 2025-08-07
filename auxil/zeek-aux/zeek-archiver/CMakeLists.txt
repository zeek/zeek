add_executable(zeek-archiver zeek-archiver.cc)

target_compile_options(zeek-archiver PRIVATE -Wall -Wno-unused -Werror=vla)

install(TARGETS zeek-archiver)
