find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)

bison_target(PACParser pac_parse.yy ${CMAKE_CURRENT_BINARY_DIR}/pac_parse.cc
             DEFINES_FILE ${CMAKE_CURRENT_BINARY_DIR}/pac_parse.h COMPILE_FLAGS "--debug")
flex_target(PACScanner pac_scan.ll ${CMAKE_CURRENT_BINARY_DIR}/pac_scan.cc)
add_flex_bison_dependency(PACScanner PACParser)
if (MSVC)
    set_property(SOURCE pac_scan.cc APPEND_STRING PROPERTY COMPILE_FLAGS "/wd4018")
else ()
    set_property(SOURCE pac_scan.cc APPEND_STRING PROPERTY COMPILE_FLAGS "-Wno-sign-compare")
endif ()

set(binpac_SRCS
    ${BISON_PACParser_INPUT}
    ${FLEX_PACScanner_INPUT}
    ${BISON_PACParser_OUTPUTS}
    ${FLEX_PACScanner_OUTPUTS}
    pac_action.cc
    pac_analyzer.cc
    pac_array.cc
    pac_attr.cc
    pac_btype.cc
    pac_case.cc
    pac_conn.cc
    pac_context.cc
    pac_cstr.cc
    pac_datadep.cc
    pac_dataptr.cc
    pac_dataunit.cc
    pac_decl.cc
    pac_embedded.cc
    pac_enum.cc
    pac_expr.cc
    pac_exttype.cc
    pac_field.cc
    pac_flow.cc
    pac_func.cc
    pac_id.cc
    pac_inputbuf.cc
    pac_let.cc
    pac_param.cc
    pac_paramtype.cc
    pac_primitive.cc
    pac_record.cc
    pac_redef.cc
    pac_regex.cc
    pac_state.cc
    pac_strtype.cc
    pac_type.cc
    pac_typedecl.cc
    pac_withinput.cc
    pac_output.cc
    pac_utils.cc
    pac_exception.cc
    pac_main.cc)

add_executable(binpac ${binpac_SRCS})

target_include_directories(binpac BEFORE PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(binpac BEFORE PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

if (MSVC)
    target_compile_options(binpac PUBLIC "/J")
    # If building separately from zeek, we need to add the libunistd subdirectory
    # so that linking doesn't fail.
    if ("${CMAKE_PROJECT_NAME}" STREQUAL "BinPAC")
        add_subdirectory(${PROJECT_SOURCE_DIR}auxil/libunistd EXCLUDE_FROM_ALL)
    endif ()
    target_link_libraries(binpac PRIVATE libunistd)
endif ()

install(TARGETS binpac DESTINATION bin)

# This is set to assist superprojects that want to build BinPac from source and
# rely on it as a target
set(BinPAC_EXE binpac CACHE STRING "BinPAC executable" FORCE)
