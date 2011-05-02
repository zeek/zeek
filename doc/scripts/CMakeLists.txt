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

    set (restFile "${basename}.rst")

    if (NOT relDstDir)
        set(docName "${basename}")
        set(dstDir "${RST_OUTPUT_DIR}")
    else ()
        set(docName "${relDstDir}/${basename}")
        set(dstDir "${RST_OUTPUT_DIR}/${relDstDir}")
    endif ()

    set(restOutput "${dstDir}/${restFile}")

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

    if (${group} STREQUAL "default" OR ${group} STREQUAL "bifs")
        set(BRO_ARGS --doc-scripts --exec '')
    else ()
        set(BRO_ARGS --doc-scripts ${srcDir}/${broInput})
    endif ()

    add_custom_command(OUTPUT ${restOutput}
        # delete any leftover state from previous bro runs
        COMMAND "${CMAKE_COMMAND}"
        ARGS -E remove_directory .state
        # generate the reST documentation using bro
        COMMAND BROPATH=${BROPATH} ${CMAKE_BINARY_DIR}/src/bro
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
# Note: the script may be located in a subdirectory off of one of the main
# directories in BROPATH.  In that case, just list the script as 'foo/bar.bro'
rest_target(${POLICY_SRC_DIR} alarm.bro                         user)
rest_target(${POLICY_SRC_DIR} arp.bro                           user)
rest_target(${POLICY_SRC_DIR} conn.bro                          user)
rest_target(${POLICY_SRC_DIR} dhcp.bro                          user)
rest_target(${POLICY_SRC_DIR} dns.bro                           user)
rest_target(${POLICY_SRC_DIR} ftp.bro                           user)
rest_target(${POLICY_SRC_DIR} http.bro                          user)
rest_target(${POLICY_SRC_DIR} http-reply.bro                    user)
rest_target(${POLICY_SRC_DIR} http-request.bro                  user)
rest_target(${POLICY_SRC_DIR} irc.bro                           user)
rest_target(${POLICY_SRC_DIR} smtp.bro                          user)
rest_target(${POLICY_SRC_DIR} ssl.bro                           user)
rest_target(${POLICY_SRC_DIR} ssl-ciphers.bro                   user)
rest_target(${POLICY_SRC_DIR} ssl-errors.bro                    user)
rest_target(${POLICY_SRC_DIR} synflood.bro                      user)
rest_target(${POLICY_SRC_DIR} tcp.bro                           user)
rest_target(${POLICY_SRC_DIR} udp.bro                           user)
rest_target(${POLICY_SRC_DIR} weird.bro                         user)
rest_target(${CMAKE_CURRENT_SOURCE_DIR} example.bro             internal)

# Finding out what scripts bro will generate documentation for by default
# can be done like: `bro --doc-scripts --exec ""`
rest_target(${POLICY_SRC_DIR} bro.init                          default)
rest_target(${POLICY_SRC_DIR} logging-ascii.bro                 default)
rest_target(${POLICY_SRC_DIR} logging.bro                       default)
rest_target(${POLICY_SRC_DIR} pcap.bro                          default)
rest_target(${POLICY_SRC_DIR} server-ports.bro                  default)
rest_target(${CMAKE_BINARY_DIR}/src bro.bif.bro                 bifs)
rest_target(${CMAKE_BINARY_DIR}/src const.bif.bro               bifs)
rest_target(${CMAKE_BINARY_DIR}/src event.bif.bro               bifs)
rest_target(${CMAKE_BINARY_DIR}/src logging.bif.bro             bifs)
rest_target(${CMAKE_BINARY_DIR}/src strings.bif.bro             bifs)
rest_target(${CMAKE_BINARY_DIR}/src types.bif.bro               bifs)

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
                  SOURCES ${DOC_SOURCES}
                  DEPENDS restdoc docclean)

# The "docclean" target removes just the Sphinx input/output directories
# from the build directory.
add_custom_target(docclean
                  COMMAND "${CMAKE_COMMAND}" -E remove_directory
                          ${DOC_SOURCE_WORKDIR}
                  COMMAND "${CMAKE_COMMAND}" -E remove_directory
                          ${DOC_OUTPUT_DIR}
                  VERBATIM)
