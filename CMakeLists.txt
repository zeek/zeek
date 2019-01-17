set(html_output_dir ${CMAKE_CURRENT_BINARY_DIR}/html)

add_custom_target(zeek-doc-html
    COMMAND sphinx-build
            -b html
            -c ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${html_output_dir}
    # Create symlink to the html output directory for convenience.
    COMMAND "${CMAKE_COMMAND}" -E create_symlink
            ${html_output_dir}
            ${CMAKE_BINARY_DIR}/html
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "[Sphinx] Generate Bro HTML documentation in ${html_output_dir}")

if (NOT TARGET doc)
  add_custom_target(doc)
endif ()

add_dependencies(doc zeek-doc-html)
