set(BROCCOLI_DOCS_SRC ${CMAKE_BINARY_DIR}/aux/broccoli/doc/html)
set(BROCCOLI_DOCS_DST ${CMAKE_BINARY_DIR}/html/broccoli-api)
set(SPHINX_INPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/sphinx_input)
set(SPHINX_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/sphinx_output)
set(BROXYGEN_SCRIPT_OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/broxygen_script_output)
set(BROXYGEN_CACHE_DIR ${CMAKE_CURRENT_BINARY_DIR}/broxygen_cache)

# Find out what BROPATH to use when executing bro.
execute_process(COMMAND ${CMAKE_BINARY_DIR}/bro-path-dev
                OUTPUT_VARIABLE BROPATH
                RESULT_VARIABLE retval
                OUTPUT_STRIP_TRAILING_WHITESPACE)
if (NOT ${retval} EQUAL 0)
    message(FATAL_ERROR "Problem setting BROPATH")
endif ()

# Configure the Sphinx config file (expand variables CMake might know about).
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/conf.py.in
               ${CMAKE_CURRENT_BINARY_DIR}/conf.py
               @ONLY)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/broxygen.conf.in
               ${CMAKE_CURRENT_BINARY_DIR}/broxygen.conf
               @ONLY)

add_custom_target(sphinxdoc
    # Copy the template documentation to build directory to use as input tree
    # for Sphinx.  This is needed because some parts are dynamically generated
    # in to that tree by Bro/Broxygen.
    COMMAND rsync -q -r --copy-links --times --delete
            --filter='protect scripts/*'
            ${CMAKE_CURRENT_SOURCE_DIR}/ ${SPHINX_INPUT_DIR}
    # Use Bro/Broxygen to dynamically generate reST for all Bro scripts.
    COMMAND BROPATH=${BROPATH}
            ${CMAKE_BINARY_DIR}/src/bro
            -X ${CMAKE_CURRENT_BINARY_DIR}/broxygen.conf
            broxygen >/dev/null
    # Rsync over the generated reST to the Sphinx source tree in the build dir.
    COMMAND rsync -q -r --copy-links --times --delete --filter='protect *.bro'
            ${BROXYGEN_SCRIPT_OUTPUT}/ ${SPHINX_INPUT_DIR}/scripts
    # Rsync over Bro scripts to the Sphinx source tree in the build dir.
    # These are used by :download: references in the generated script docs.
    COMMAND rsync -q -r --copy-links --times --delete
            --filter='protect /base/bif/*' --filter='protect *.rst'
            --filter='include */' --filter='include *.bro' --filter='exclude *'
            ${CMAKE_SOURCE_DIR}/scripts/ ${SPHINX_INPUT_DIR}/scripts
    # Rsync over Bro scripts created by BIF compiler to the Sphinx source tree.
    COMMAND rsync -q -r --copy-links --times --delete
            --filter='protect *.rst' --filter='include */'
            --filter='include *.bro' --filter='exclude *'
            ${CMAKE_BINARY_DIR}/scripts/base/bif/
            ${SPHINX_INPUT_DIR}/scripts/base/bif
    # Use Sphinx to build HTML.
    COMMAND sphinx-build
            -b html
            -c ${CMAKE_CURRENT_BINARY_DIR}
            -d ${SPHINX_OUTPUT_DIR}/doctrees
            ${SPHINX_INPUT_DIR}
            ${SPHINX_OUTPUT_DIR}/html
    # Create symlink to the html output directory for convenience.
    COMMAND "${CMAKE_COMMAND}" -E create_symlink
            ${SPHINX_OUTPUT_DIR}/html
            ${CMAKE_BINARY_DIR}/html
    # Copy Broccoli API reference into output dir if it exists.
    COMMAND test -d ${BROCCOLI_DOCS_SRC} &&
            ( rm -rf ${BROCCOLI_DOCS_DST} &&
              cp -r ${BROCCOLI_DOCS_SRC} ${BROCCOLI_DOCS_DST} ) || true
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "[Sphinx] Generate HTML documentation in ${CMAKE_BINARY_DIR}/html")

add_dependencies(sphinxdoc bro)

add_custom_target(sphinxdoc_clean
    COMMAND "${CMAKE_COMMAND}" -E remove_directory ${SPHINX_INPUT_DIR}
    COMMAND "${CMAKE_COMMAND}" -E remove_directory ${SPHINX_OUTPUT_DIR}
    COMMAND "${CMAKE_COMMAND}" -E remove_directory ${BROXYGEN_SCRIPT_OUTPUT}
    COMMAND "${CMAKE_COMMAND}" -E remove_directory ${BROXYGEN_CACHE_DIR}
    VERBATIM)

add_custom_target(doc)
add_custom_target(docclean)
add_dependencies(doc sphinxdoc)
add_dependencies(docclean sphinxdoc_clean)
