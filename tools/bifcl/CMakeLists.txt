find_package(BISON REQUIRED)
find_package(FLEX REQUIRED)

set(BISON_FLAGS "--debug")

# BIF parser/scanner
bison_target(BIFParser builtin-func.y ${CMAKE_CURRENT_BINARY_DIR}/bif_parse.cc
             DEFINES_FILE ${CMAKE_CURRENT_BINARY_DIR}/bif_parse.h COMPILE_FLAGS "${BISON_FLAGS}")
flex_target(BIFScanner builtin-func.l ${CMAKE_CURRENT_BINARY_DIR}/bif_lex.cc)
add_flex_bison_dependency(BIFScanner BIFParser)

set(bifcl_SRCS ${BISON_BIFParser_INPUT} ${FLEX_BIFScanner_INPUT} ${BISON_BIFParser_OUTPUTS}
               ${FLEX_BIFScanner_OUTPUTS} bif_arg.cc module_util.cc)

set(bifcl_bison_generated_files
    ${CMAKE_CURRENT_BINARY_DIR}/bif_parse.cc ${CMAKE_CURRENT_BINARY_DIR}/bif_parse.h
    ${CMAKE_CURRENT_BINARY_DIR}/bif_lex.cc)

set_source_files_properties(${bifcl_bison_generated_files} PROPERTIES SKIP_LINTING ON)

add_executable(bifcl ${bifcl_SRCS})
target_include_directories(bifcl BEFORE PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
zeek_target_add_linters(bifcl)

if (MSVC)
    target_compile_options(bifcl PUBLIC "/J") # Similar to -funsigned-char on other platforms
    target_compile_options(bifcl PUBLIC "/wd4018") # Similar to -Wno-sign-compare on other platforms
    target_link_libraries(bifcl PRIVATE libunistd)
else ()
    target_compile_options(bifcl PUBLIC "-Wno-sign-compare")
endif ()

install(TARGETS bifcl DESTINATION bin)
