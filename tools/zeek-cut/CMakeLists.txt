add_executable(zeek-cut zeek-cut.c)

if (MSVC)
    target_link_libraries(zeek-cut PRIVATE libunistd)
endif ()

install(TARGETS zeek-cut)
install(FILES zeek-cut.1 DESTINATION ${ZEEK_MAN_INSTALL_PATH}/man1)
