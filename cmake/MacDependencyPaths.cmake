if (NOT _MAC_DEPENDENCY_PATHS)
set(_MAC_DEPENDENCY_PATHS)
    # As of CMake 2.8.3, Fink and MacPorts search paths are appended to the
    # default search prefix paths, but the nicer thing would be if they are
    # prepended to the default, so that is fixed here.
    if (APPLE) 
        list(INSERT CMAKE_SYSTEM_PREFIX_PATH 0 /opt/local) # MacPorts
        list(INSERT CMAKE_SYSTEM_PREFIX_PATH 0 /sw)        # Fink
    endif ()
endif ()
