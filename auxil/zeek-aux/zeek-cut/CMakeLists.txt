set(zeekcut_SRCS zeek-cut.c)

add_executable(zeek-cut ${zeekcut_SRCS})

install(TARGETS zeek-cut)
install(FILES zeek-cut.1 DESTINATION ${ZEEK_MAN_INSTALL_PATH}/man1)
