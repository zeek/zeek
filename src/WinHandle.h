// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#ifdef _MSC_VER

#include <windows.h>
#include <memory>

namespace zeek::detail {

/**
 * RAII wrapper for Windows HANDLEs. Automatically calls CloseHandle on destruction.
 */
struct WinHandleDeleter {
    using pointer = HANDLE;
    void operator()(HANDLE h) const noexcept {
        if ( h && h != INVALID_HANDLE_VALUE )
            CloseHandle(h);
    }
};
using UniqueWinHandle = std::unique_ptr<void, WinHandleDeleter>;

} // namespace zeek::detail

#endif
