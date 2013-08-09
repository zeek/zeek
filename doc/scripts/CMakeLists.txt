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
# broInput: the file name of a bro policy script, any path prefix of this
#     argument will be used to derive what path under scripts/ the generated
#     documentation will be placed.
# group: optional name of group that the script documentation will belong to.
#     If this is not given, the group is automatically set to any path portion
#     of the broInput argument.
#
# In addition to adding the makefile target, several CMake variables are set:
#
# MASTER_POLICY_INDEX_TEXT: a running list of policy scripts docs that have
#   been generated so far, formatted such that it can be appended to a file
#   that ends in a Sphinx toctree directive
# ALL_REST_OUTPUTS: a running list (the CMake list type) of all reST docs
#   that are to be generated
# MASTER_GROUP_LIST: a running list (the CMake list type) of all script groups
# MASTER_PKG_LIST: a running list (the CMake list type) of all script groups
#   that were defived from the path portion of the broInput argument
# ${group}_files: a running list of files belonging to a given group, from
#   which summary text can be extracted at build time
# ${group}_doc_names: a running list of reST style document names that can be
#   given to a :doc: role, shared indices with ${group}_files

macro(REST_TARGET srcDir broInput)
    set(absSrcPath ${srcDir}/${broInput})
    get_filename_component(basename ${broInput} NAME)
    string(REPLACE .bro "" basename ${basename})
    get_filename_component(extension ${broInput} EXT)
    get_filename_component(relDstDir ${broInput} PATH)

    set(sumTextSrc ${absSrcPath})
    set(ogSourceFile ${absSrcPath})

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

    set(MASTER_POLICY_INDEX_TEXT
        "${MASTER_POLICY_INDEX_TEXT}\n   ${docName} <${docName}>")
    list(APPEND ALL_REST_OUTPUTS ${restOutput})

    if (NOT "${ARGN}" STREQUAL "")
        set(group ${ARGN})
    elseif (relDstDir)
        set(group ${relDstDir}/index)
        # add package index to master package list if not already in it
        # and if a __load__.bro exists in the original script directory
        list(FIND MASTER_PKG_LIST ${relDstDir} _found)
        if (_found EQUAL -1)
            if (EXISTS ${CMAKE_SOURCE_DIR}/scripts/${relDstDir}/__load__.bro)
                list(APPEND MASTER_PKG_LIST ${relDstDir})
            endif ()
        endif ()
    else ()
        set(group "")
    endif ()

    if (NOT "${group}" STREQUAL "")
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
    endif ()

    add_custom_command(OUTPUT ${restOutput}
        # delete any leftover state from previous bro runs
        COMMAND "${CMAKE_COMMAND}"
        ARGS -E remove_directory .state
        # generate the reST documentation using bro
        COMMAND BROPATH=${BROPATH}:${srcDir} BROMAGIC=${CMAKE_SOURCE_DIR}/magic/database ${CMAKE_BINARY_DIR}/src/bro
        ARGS -b -Z ${broInput} || (rm -rf .state *.log *.rst && exit 1)
        # move generated doc into a new directory tree that
        # defines the final structure of documents
        COMMAND "${CMAKE_COMMAND}"
        ARGS -E make_directory ${dstDir}
        COMMAND "${CMAKE_COMMAND}"
        ARGS -E copy ${restFile} ${restOutput}
        # copy the bro or bif script, too
        COMMAND "${CMAKE_COMMAND}"
        ARGS -E copy ${ogSourceFile} ${dstDir}
        # clean up the build directory
        COMMAND rm
        ARGS -rf .state *.log *.rst
        DEPENDS bro
        DEPENDS ${absSrcPath}
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "[Bro] Generating reST docs for ${broInput}"
    )

endmacro(REST_TARGET)

# Schedule Bro scripts for which to generate documentation.
include(DocSourcesList.cmake)

# Macro for generating reST docs that are independent of any particular Bro
# script.
macro(INDEPENDENT_REST_TARGET reST_file)
    add_custom_command(OUTPUT ${reST_file}
        # delete any leftover state from previous bro runs
        COMMAND "${CMAKE_COMMAND}"
        ARGS -E remove_directory .state
        # generate the reST documentation using bro
        COMMAND BROPATH=${BROPATH}:${srcDir} BROMAGIC=${CMAKE_SOURCE_DIR}/magic/database ${CMAKE_BINARY_DIR}/src/bro
        ARGS -b -Z base/init-bare.bro || (rm -rf .state *.log *.rst && exit 1)
        # move generated doc into a new directory tree that
        # defines the final structure of documents
        COMMAND "${CMAKE_COMMAND}"
        ARGS -E make_directory ${dstDir}
        COMMAND "${CMAKE_COMMAND}"
        ARGS -E copy ${reST_file} ${dstDir}
        # clean up the build directory
        COMMAND rm
        ARGS -rf .state *.log *.rst
        DEPENDS bro
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "[Bro] Generating reST docs for ${reST_file}"
    )
    list(APPEND ALL_REST_OUTPUTS ${reST_file})
endmacro(INDEPENDENT_REST_TARGET)

independent_rest_target(proto-analyzers.rst)
independent_rest_target(file-analyzers.rst)

# create temporary list of all docs to include in the master policy/index file
file(WRITE ${MASTER_POLICY_INDEX} "${MASTER_POLICY_INDEX_TEXT}")

# create the temporary list of all packages to include in the master
# policy/packages.rst file
set(MASTER_PKG_INDEX_TEXT "")
foreach (pkg ${MASTER_PKG_LIST})
    set(MASTER_PKG_INDEX_TEXT
        "${MASTER_PKG_INDEX_TEXT}\n:doc:`${pkg} <${pkg}/index>`\n")
    if (EXISTS ${CMAKE_SOURCE_DIR}/scripts/${pkg}/README)
        file(STRINGS ${CMAKE_SOURCE_DIR}/scripts/${pkg}/README pkgreadme)
        foreach (line ${pkgreadme})
            set(MASTER_PKG_INDEX_TEXT "${MASTER_PKG_INDEX_TEXT}\n    ${line}")
        endforeach ()
        set(MASTER_PKG_INDEX_TEXT "${MASTER_PKG_INDEX_TEXT}\n")
    endif ()
endforeach ()
file(WRITE ${MASTER_PACKAGE_INDEX} "${MASTER_PKG_INDEX_TEXT}")

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
            message(STATUS "Broxygen: remove stale reST doc: ${_doc}")
            string(REPLACE .rst .bro _brofile ${_doc})
            if (EXISTS ${_brofile})
                file(REMOVE ${_brofile})
                message(STATUS "Broxygen: remove stale bro source: ${_brofile}")
            endif ()
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
