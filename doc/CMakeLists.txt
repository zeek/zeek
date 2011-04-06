set(POLICY_SRC_DIR ${PROJECT_SOURCE_DIR}/policy)
set(DOC_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/out)
set(DOC_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/source)
set(DOC_SOURCE_WORKDIR ${CMAKE_CURRENT_BINARY_DIR}/source)

file(GLOB_RECURSE DOC_SOURCES FOLLOW_SYMLINKS "*")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/conf.py.in
               ${CMAKE_CURRENT_BINARY_DIR}/conf.py
               @ONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_reST_docs.py.in
               ${CMAKE_CURRENT_BINARY_DIR}/generate_reST_docs.py
               @ONLY)

add_custom_target(doc
                  COMMAND "${CMAKE_COMMAND}" -E copy_directory
                          ${DOC_SOURCE_DIR}
                          ${DOC_SOURCE_WORKDIR}
                  COMMAND python generate_reST_docs.py
                  COMMAND sphinx-build
                          -b html
                          -c ${CMAKE_CURRENT_BINARY_DIR}
                          -d ${DOC_OUTPUT_DIR}/doctrees
                          ${DOC_SOURCE_WORKDIR}
                          ${DOC_OUTPUT_DIR}/html
                  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                  COMMENT "[Sphinx] Generating Script Documentation"
                  VERBATIM
                  # SOURCES just adds stuff to IDE projects as a convienience
                  SOURCES ${DOC_SOURCES})

add_dependencies(doc bro)
# TODO: add dependency that's a check for `python`, `sphinx-build`, etc.

add_custom_target(doc-clean
                  COMMAND "${CMAKE_COMMAND}" -E remove_directory
                          ${CMAKE_CURRENT_BINARY_DIR}/source
                  COMMAND "${CMAKE_COMMAND}" -E remove_directory
                          ${DOC_OUTPUT_DIR}
                  VERBATIM)
