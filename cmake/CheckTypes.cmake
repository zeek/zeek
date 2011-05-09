include(CheckTypeSize)

check_type_size("long int" SIZEOF_LONG_INT)
check_type_size("long long" SIZEOF_LONG_LONG)
check_type_size("void *" SIZEOF_VOID_P)

# checks existence of ${_type}, and if it does not, sets CMake variable ${_var}
# to alternative type, ${_alt_type}
macro(CheckType _type _alt_type _var)
    # don't perform check if we have a result from a previous CMake run
    if (NOT HAVE_${_var})
        check_type_size(${_type} ${_var})
        if (NOT ${_var})
            set(${_var} ${_alt_type})
        else ()
            unset(${_var})
            unset(${_var} CACHE)
        endif ()
    endif ()
endmacro(CheckType _type _alt_type _var)

set(CMAKE_EXTRA_INCLUDE_FILES sys/types.h)
CheckType(int32_t   int     int32_t)
CheckType(u_int32_t u_int   u_int32_t)
CheckType(u_int16_t u_short u_int16_t)
CheckType(u_int8_t  u_char  u_int8_t)
set(CMAKE_EXTRA_INCLUDE_FILES)

set(CMAKE_EXTRA_INCLUDE_FILES sys/socket.h)
CheckType(socklen_t int     socklen_t)
set(CMAKE_EXTRA_INCLUDE_FILES)
