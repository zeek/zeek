
project(BroHILTI C CXX)
cmake_minimum_required(VERSION 2.6.3 FATAL_ERROR)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake)

find_package(HILTI)

if ( ENABLE_HILTI )
   if ( NOT HILTI_FOUND )
       message(FATAL_ERROR "HILTI not found")
   endif()

   set(HAVE_HILTI true)
   set(CMAKE_C_COMPILER   "${HILTI_CLANG_EXEC}")
   set(CMAKE_CXX_COMPILER "${HILTI_CLANGXX_EXEC}")
   set(CMAKE_C_FLAGS      "-I ${CMAKE_BINARY_DIR} ${CMAKE_C_FLAGS} -fno-color-diagnostics")
   set(CMAKE_CXX_FLAGS    "-I ${CMAKE_BINARY_DIR} ${CMAKE_CXX_FLAGS} -fno-color-diagnostics -DHILTI_CXX11 ${HILTI_CXX_FLAGS}")
   set(CMAKE_LD_FLAGS     "${CMAKE_LD_FLAGS} ${HILTI_LD_FLAGS}")
   set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_LD_FLAGS} ${HILTI_LD_FLAGS}")

   set(SRCS
     Converter.cc
     Loader.cc
     Pac2AST.cc
     Pac2Analyzer.cc
     Runtime.cc
     )

   add_library(brohilti STATIC ${SRCS})
   add_dependencies(brohilti generate_bifs)

else ()
   set(HAVE_HILTI false)
endif ()

set_property(GLOBAL PROPERTY HLT_HAVE_HILTI   "${HAVE_HILTI}")
set_property(GLOBAL PROPERTY HLT_HILTI_FOUND  "${HILTI_FOUND}")
set_property(GLOBAL PROPERTY HLT_HILTI_CONFIG "${HILTI_CONFIG}")
set_property(GLOBAL PROPERTY HLT_LD_FLAGS     "${HILTI_LD_FLAGS}")
set_property(GLOBAL PROPERTY HLT_LIBS_STATIC  "${HILTI_LIBS_STATIC}")
set_property(GLOBAL PROPERTY HLT_LIBS_SHARED  "${HILTI_LIBS_SHARED}")
set_property(GLOBAL PROPERTY HLT_CLANG_EXEC   "${HILTI_CLANG_EXEC}")
set_property(GLOBAL PROPERTY HLT_CLANGXX_EXEC "${HILTI_CLANGXX_EXEC}")

