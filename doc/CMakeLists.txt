set(BIF_SRC_DIR ${PROJECT_SOURCE_DIR}/src)
set(RST_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/rest_output)
set(DOC_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/out)
set(DOC_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(DOC_SOURCE_WORKDIR ${CMAKE_CURRENT_BINARY_DIR}/sphinx-sources)

set(MASTER_POLICY_INDEX ${CMAKE_CURRENT_BINARY_DIR}/scripts/policy_index)
set(MASTER_PACKAGE_INDEX ${CMAKE_CURRENT_BINARY_DIR}/scripts/pkg_index)

file(GLOB_RECURSE DOC_SOURCES FOLLOW_SYMLINKS "*")

# configure the Sphinx config file (expand variables CMake might know about)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/conf.py.in
               ${CMAKE_CURRENT_BINARY_DIR}/conf.py
               @ONLY)

add_subdirectory(scripts)

# The "broxygen" target generates reST documentation for any outdated bro
# scripts and then uses Sphinx to generate HTML documentation from the reST
add_custom_target(broxygen
                  # copy the template documentation to the build directory
                  # to give as input for sphinx
                  COMMAND rsync -r --copy-links --times
                          ${DOC_SOURCE_DIR}/
                          ${DOC_SOURCE_WORKDIR}
                  # copy generated policy script documentation into the
                  # working copy of the template documentation
                  COMMAND rsync -r --copy-links --times
                          ${RST_OUTPUT_DIR}/
                          ${DOC_SOURCE_WORKDIR}/scripts
                  # append to the master index of all policy scripts
                  COMMAND cat ${MASTER_POLICY_INDEX} >>
                          ${DOC_SOURCE_WORKDIR}/scripts/scripts.rst
                  # append to the master index of all policy packages
                  COMMAND cat ${MASTER_PACKAGE_INDEX} >>
                          ${DOC_SOURCE_WORKDIR}/scripts/packages.rst
                  # construct a reST file for each group
                  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/bin/group_index_generator.py
                          ${CMAKE_CURRENT_BINARY_DIR}/scripts/group_list
                          ${CMAKE_CURRENT_BINARY_DIR}/scripts
                          ${DOC_SOURCE_WORKDIR}/scripts
                  # tell sphinx to generate html
                  COMMAND sphinx-build
                          -b html
                          -c ${CMAKE_CURRENT_BINARY_DIR}
                          -d ${DOC_OUTPUT_DIR}/doctrees
                          ${DOC_SOURCE_WORKDIR}
                          ${DOC_OUTPUT_DIR}/html
                  # create symlink to the html output directory for convenience
                  COMMAND "${CMAKE_COMMAND}" -E create_symlink
                          ${DOC_OUTPUT_DIR}/html
                          ${CMAKE_BINARY_DIR}/html
                  # copy Broccoli API reference into output dir if it exists
                  COMMAND test -d ${CMAKE_BINARY_DIR}/aux/broccoli/doc/html && ( rm -rf ${CMAKE_BINARY_DIR}/html/broccoli-api && cp -r ${CMAKE_BINARY_DIR}/aux/broccoli/doc/html ${CMAKE_BINARY_DIR}/html/broccoli-api ) || true
                  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                  COMMENT "[Sphinx] Generating HTML policy script docs"
                  # SOURCES just adds stuff to IDE projects as a convenience
                  SOURCES ${DOC_SOURCES})

# The "broxygenclean" target removes just the Sphinx input/output directories
# from the build directory.
add_custom_target(broxygenclean
                  COMMAND "${CMAKE_COMMAND}" -E remove_directory
                          ${DOC_SOURCE_WORKDIR}
                  COMMAND "${CMAKE_COMMAND}" -E remove_directory
                          ${DOC_OUTPUT_DIR}
                  VERBATIM)

add_dependencies(broxygen restdoc)

add_custom_target(doc)
add_custom_target(docclean)
add_dependencies(doc broxygen)
add_dependencies(docclean broxygenclean restclean)
