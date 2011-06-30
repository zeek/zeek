set(POLICY_SRC_DIR ${PROJECT_SOURCE_DIR}/policy)
set(BIF_SRC_DIR ${PROJECT_SOURCE_DIR}/src)
set(RST_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/rest_output)
set(DOC_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/out)
set(DOC_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/source)
set(DOC_SOURCE_WORKDIR ${CMAKE_CURRENT_BINARY_DIR}/source)

file(GLOB_RECURSE DOC_SOURCES FOLLOW_SYMLINKS "*")

# configure the Sphinx config file (expand variables CMake might know about)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/conf.py.in
               ${CMAKE_CURRENT_BINARY_DIR}/conf.py
               @ONLY)

# find out what BROPATH to use when executing bro
execute_process(COMMAND ${CMAKE_BINARY_DIR}/bro-path-dev
                OUTPUT_VARIABLE BROPATH
                RESULT_VARIABLE retval
                OUTPUT_STRIP_TRAILING_WHITESPACE)
if (NOT ${retval} EQUAL 0)
    message(FATAL_ERROR "Problem setting BROPATH")
endif ()

# This macro is used to add a new makefile target for reST policy script
# documentation that can be generated using Bro itself to parse policy scripts.
# It's called like:
#
#     rest_target(srcDir broInput [group])
#
# srcDir: the directory which contains broInput
# broInput: the file name of a bro policy script
# group: optional name of group that the script documentation will belong to
#
# In addition to adding the makefile target, several CMake variables are set:
#
# MASTER_POLICY_INDEX_TEXT: a running list of policy scripts docs that have
#   been generated so far, formatted such that it can be appended to a file
#   that ends in a Sphinx toctree directive
# ALL_REST_OUTPUTS: a running list (the CMake list type) of all reST docs
#   that are to be generated
# MASTER_GROUP_LIST: a running list (the CMake list type) of all script groups
# ${group}_files: a running list of files belonging to a given group, from
#   which summary text can be extracted at build time
# ${group}_doc_names: a running list of reST style document names that can be
#   given to a :doc: role, shared indices with ${group}_files
#
macro(REST_TARGET srcDir broInput)
    get_filename_component(basename ${broInput} NAME_WE)
    get_filename_component(extension ${broInput} EXT)
    get_filename_component(relDstDir ${broInput} PATH)

    set(sumTextSrc ${srcDir}/${broInput})
    if (${extension} STREQUAL ".bif.bro")
        set(basename "${basename}.bif")
        # the summary text is taken at configure time, but .bif.bro files
        # may not have been generated yet, so read .bif file instead
        set(sumTextSrc ${BIF_SRC_DIR}/${basename})
    elseif (${extension} STREQUAL ".init")
        set(basename "${basename}.init")
    endif ()

    if (NOT relDstDir)
        set(docName "${basename}")
        set(dstDir "${RST_OUTPUT_DIR}")
    else ()
        set(docName "${relDstDir}/${basename}")
        set(dstDir "${RST_OUTPUT_DIR}/${relDstDir}")
    endif ()

    set(restFile "${docName}.rst")
    string(REPLACE "/" "^" restFile ${restFile})
    set(restOutput "${dstDir}/${basename}.rst")

    set(indexEntry "   ${docName} <${docName}>")
    set(MASTER_POLICY_INDEX_TEXT "${MASTER_POLICY_INDEX_TEXT}\n${indexEntry}")
    list(APPEND ALL_REST_OUTPUTS ${restOutput})

    if (NOT "${ARGN}" STREQUAL "")
        set(group ${ARGN})
        # add group to master group list if not already in it
        list(FIND MASTER_GROUP_LIST ${group} _found)
        if (_found EQUAL -1)
            list(APPEND MASTER_GROUP_LIST ${group})
            if (MASTER_GROUP_LIST_TEXT)
               set(MASTER_GROUP_LIST_TEXT "${MASTER_GROUP_LIST_TEXT}\n${group}")
            else ()
               set(MASTER_GROUP_LIST_TEXT "${group}")
            endif ()
        endif ()

        list(APPEND ${group}_files ${sumTextSrc})
        list(APPEND ${group}_doc_names ${docName})
    else ()
        set(group "")
    endif ()

    if ("${group}" STREQUAL "default" OR "${group}" STREQUAL "bifs")
        set(BRO_ARGS --doc-scripts --exec '')
    else ()
        set(BRO_ARGS --doc-scripts ${broInput})
    endif ()

    add_custom_command(OUTPUT ${restOutput}
        # delete any leftover state from previous bro runs
        COMMAND "${CMAKE_COMMAND}"
        ARGS -E remove_directory .state
        # generate the reST documentation using bro
        COMMAND BROPATH=${BROPATH}:${srcDir} ${CMAKE_BINARY_DIR}/src/bro
        ARGS ${BRO_ARGS} || (rm -rf .state *.log *.rst && exit 1)
        # move generated doc into a new directory tree that
        # defines the final structure of documents
        COMMAND "${CMAKE_COMMAND}"
        ARGS -E make_directory ${dstDir}
        COMMAND "${CMAKE_COMMAND}"
        ARGS -E copy ${restFile} ${restOutput}
        # copy the bro policy script, too
        COMMAND "${CMAKE_COMMAND}"
        ARGS -E copy ${srcDir}/${broInput} ${dstDir}
        # clean up the build directory
        COMMAND rm
        ARGS -rf .state *.log *.rst
        DEPENDS bro
        DEPENDS ${srcDir}/${broInput}
        COMMENT "[Bro] Generating reST docs for ${broInput}"
    )

endmacro(REST_TARGET)

# Schedule Bro scripts for which to generate documentation.
#
# Note: any path prefix of the script (2nd argument of rest_target macro)
# will be used to derive what path under policy/ the generated documentation
# will be placed.

rest_target(${CMAKE_CURRENT_SOURCE_DIR} example.bro)

rest_target(${CMAKE_BINARY_DIR}/src bro.bif.bro)
rest_target(${CMAKE_BINARY_DIR}/src const.bif.bro)
rest_target(${CMAKE_BINARY_DIR}/src event.bif.bro)
rest_target(${CMAKE_BINARY_DIR}/src logging.bif.bro)
rest_target(${CMAKE_BINARY_DIR}/src strings.bif.bro)
rest_target(${CMAKE_BINARY_DIR}/src types.bif.bro)

set(psd ${POLICY_SRC_DIR})

rest_target(${psd} bro.init)
rest_target(${psd} site.bro)

rest_target(${psd} detectors/http-MHR.bro)

rest_target(${psd} frameworks/communication/base.bro)
rest_target(${psd} frameworks/communication/listen-clear.bro)
rest_target(${psd} frameworks/communication/listen-ssl.bro)

rest_target(${psd} frameworks/dpd/base.bro)
rest_target(${psd} frameworks/dpd/dyn-disable.bro)
rest_target(${psd} frameworks/dpd/packet-segment-logging.bro)

rest_target(${psd} frameworks/intel/base.bro)

rest_target(${psd} frameworks/logging/base.bro)
rest_target(${psd} frameworks/logging/plugins/ascii.bro)

rest_target(${psd} frameworks/metrics/base.bro)
rest_target(${psd} frameworks/metrics/conn-example.bro)
rest_target(${psd} frameworks/metrics/http-example.bro)

rest_target(${psd} frameworks/notice/action-filters.bro)
rest_target(${psd} frameworks/notice/base.bro)
rest_target(${psd} frameworks/notice/weird.bro)

rest_target(${psd} frameworks/packet-filter/base.bro)
rest_target(${psd} frameworks/packet-filter/netstats.bro)

rest_target(${psd} frameworks/signatures/base.bro)

rest_target(${psd} frameworks/software/base.bro)
rest_target(${psd} frameworks/software/vulnerable.bro)

rest_target(${psd} integration/barnyard2/base.bro)
rest_target(${psd} integration/barnyard2/event.bro)
rest_target(${psd} integration/barnyard2/types.bro)

rest_target(${psd} protocols/conn/base.bro)
rest_target(${psd} protocols/conn/contents.bro)
rest_target(${psd} protocols/conn/inactivity.bro)
rest_target(${psd} protocols/conn/known-hosts.bro)
rest_target(${psd} protocols/conn/known-services.bro)

rest_target(${psd} protocols/dns/auth-addl.bro)
rest_target(${psd} protocols/dns/base.bro)
rest_target(${psd} protocols/dns/consts.bro)
rest_target(${psd} protocols/dns/detect.bro)

rest_target(${psd} protocols/ftp/base.bro)
rest_target(${psd} protocols/ftp/detect.bro)
rest_target(${psd} protocols/ftp/file-extract.bro)
rest_target(${psd} protocols/ftp/software.bro)
rest_target(${psd} protocols/ftp/utils-commands.bro)

rest_target(${psd} protocols/http/base.bro)
rest_target(${psd} protocols/http/detect-intel.bro)
rest_target(${psd} protocols/http/detect-sqli.bro)
rest_target(${psd} protocols/http/detect-webapps.bro)
rest_target(${psd} protocols/http/file-extract.bro)
rest_target(${psd} protocols/http/file-hash.bro)
rest_target(${psd} protocols/http/file-ident.bro)
rest_target(${psd} protocols/http/headers.bro)
rest_target(${psd} protocols/http/software.bro)
rest_target(${psd} protocols/http/utils.bro)
rest_target(${psd} protocols/http/var-extraction-cookies.bro)
rest_target(${psd} protocols/http/var-extraction-uri.bro)

rest_target(${psd} protocols/irc/base.bro)
rest_target(${psd} protocols/irc/dcc-send.bro)

rest_target(${psd} protocols/mime/base.bro)
rest_target(${psd} protocols/mime/file-extract.bro)
rest_target(${psd} protocols/mime/file-hash.bro)
rest_target(${psd} protocols/mime/file-ident.bro)

rest_target(${psd} protocols/smtp/base.bro)
rest_target(${psd} protocols/smtp/detect.bro)
rest_target(${psd} protocols/smtp/software.bro)

rest_target(${psd} protocols/ssh/base.bro)
rest_target(${psd} protocols/ssh/software.bro)

#rest_target(${psd} protocols/ssl/base.bro)
#rest_target(${psd} protocols/ssl/ssl-ciphers.bro)
#rest_target(${psd} protocols/ssl/ssl-errors.bro)
#rest_target(${psd} protocols/ssl/ssl.bro)
#rest_target(${psd} protocols/ssl/validate.bro)

rest_target(${psd} protocols/syslog/base.bro)
rest_target(${psd} protocols/syslog/consts.bro)

rest_target(${psd} tuning/defaults/packet-fragments.bro)
rest_target(${psd} tuning/defaults/remove-high-volume-notices.bro)
rest_target(${psd} tuning/track-all-assets.bro)

rest_target(${psd} utils/addrs.bro)
rest_target(${psd} utils/conn_ids.bro)
rest_target(${psd} utils/directions-and-hosts.bro)
rest_target(${psd} utils/files.bro)
rest_target(${psd} utils/numbers.bro)
rest_target(${psd} utils/paths.bro)
rest_target(${psd} utils/pattern.bro)
rest_target(${psd} utils/strings.bro)
rest_target(${psd} utils/thresholds.bro)

# create temporary list of all docs to include in the master policy/index file
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/tmp_policy_index
    "${MASTER_POLICY_INDEX_TEXT}")

# create temporary file containing list of all groups
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/group_list
    "${MASTER_GROUP_LIST_TEXT}")

# create temporary files containing list of each source file in a given group
foreach (group ${MASTER_GROUP_LIST})
    if (EXISTS ${CMAKE_CURRENT_BINARY_DIR}/${group}_files)
        file(REMOVE ${CMAKE_CURRENT_BINARY_DIR}/${group}_files)
    endif ()
    if (EXISTS ${CMAKE_CURRENT_BINARY_DIR}/${group}_doc_names)
        file(REMOVE ${CMAKE_CURRENT_BINARY_DIR}/${group}_doc_names)
    endif ()
    foreach (src ${${group}_files})
        file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/${group}_files "${src}\n")
    endforeach ()
    foreach (dname ${${group}_doc_names})
        file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/${group}_doc_names "${dname}\n")
    endforeach ()
endforeach ()

# remove previously generated docs no longer scheduled for generation
if (EXISTS ${RST_OUTPUT_DIR})
    file(GLOB_RECURSE EXISTING_REST_DOCS "${RST_OUTPUT_DIR}/*.rst")
    foreach (_doc ${EXISTING_REST_DOCS})
        list(FIND ALL_REST_OUTPUTS ${_doc} _found)
        if (_found EQUAL -1)
            file(REMOVE ${_doc})
            message(STATUS "Removing stale reST doc: ${_doc}")
        endif ()
    endforeach ()
endif ()

# The "restdoc" target uses Bro to parse policy scripts in order to
# generate reST documentation from them.
add_custom_target(restdoc
                  # create symlink to the reST output directory for convenience
                  COMMAND "${CMAKE_COMMAND}" -E create_symlink
                          ${RST_OUTPUT_DIR}
                          ${CMAKE_BINARY_DIR}/reST
                  DEPENDS ${ALL_REST_OUTPUTS})

# The "restclean" target removes all generated reST documentation from the
# build directory.
add_custom_target(restclean
                  COMMAND "${CMAKE_COMMAND}" -E remove_directory
                          ${RST_OUTPUT_DIR}
                  VERBATIM)

# The "doc" target generates reST documentation for any outdated bro scripts
# and then uses Sphinx to generate HTML documentation from the reST
add_custom_target(doc
                  # copy the template documentation to the build directory
                  # to give as input for sphinx
                  COMMAND "${CMAKE_COMMAND}" -E copy_directory
                          ${DOC_SOURCE_DIR}
                          ${DOC_SOURCE_WORKDIR}
                  # copy generated policy script documentation into the
                  # working copy of the template documentation
                  COMMAND "${CMAKE_COMMAND}" -E copy_directory
                          ${RST_OUTPUT_DIR}
                          ${DOC_SOURCE_WORKDIR}/policy
                  # append to the master index of all policy scripts
                  COMMAND cat ${CMAKE_CURRENT_BINARY_DIR}/tmp_policy_index >>
                          ${DOC_SOURCE_WORKDIR}/policy/index.rst
                  # construct a reST file for each group
                  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/group_index_generator.py
                          ${CMAKE_CURRENT_BINARY_DIR}/group_list
                          ${CMAKE_CURRENT_BINARY_DIR}
                          ${DOC_SOURCE_WORKDIR}
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
                  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                  COMMENT "[Sphinx] Generating HTML policy script docs"
                  # SOURCES just adds stuff to IDE projects as a convienience
                  SOURCES ${DOC_SOURCES})

# The "docclean" target removes just the Sphinx input/output directories
# from the build directory.
add_custom_target(docclean
                  COMMAND "${CMAKE_COMMAND}" -E remove_directory
                          ${DOC_SOURCE_WORKDIR}
                  COMMAND "${CMAKE_COMMAND}" -E remove_directory
                          ${DOC_OUTPUT_DIR}
                  VERBATIM)

add_dependencies(doc docclean restdoc)
