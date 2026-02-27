add_executable(zeek-cut zeek-cut.c)

install(TARGETS zeek-cut)
install(FILES zeek-cut.1 DESTINATION ${ZEEK_MAN_INSTALL_PATH}/man1)
