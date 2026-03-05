// See the file "COPYING" in the main distribution directory for copyright.

#ifdef _WIN32

#include "zeek/input/InputFile.h"

#include <fcntl.h>
#include <io.h>
#include <windows.h>

namespace zeek::input::reader::detail {

// A streambuf backed by a Windows HANDLE opened with FILE_SHARE_DELETE,
// allowing external renames while the file is open (matching POSIX semantics).
class WinShareDeleteBuf : public std::streambuf {
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    static constexpr size_t BUF_SIZE = 8192;
    char buffer_[BUF_SIZE];

protected:
    int_type underflow() override {
        if ( gptr() < egptr() )
            return traits_type::to_int_type(*gptr());

        DWORD bytes_read = 0;
        if ( ! ReadFile(handle_, buffer_, BUF_SIZE, &bytes_read, NULL) || bytes_read == 0 )
            return traits_type::eof();

        setg(buffer_, buffer_, buffer_ + bytes_read);
        return traits_type::to_int_type(*gptr());
    }

    int sync() override {
        // Seek back to account for unread buffered data so the next read
        // starts from the correct file position.
        if ( handle_ != INVALID_HANDLE_VALUE && gptr() < egptr() ) {
            LONG dist = -static_cast<LONG>(egptr() - gptr());
            SetFilePointer(handle_, dist, NULL, FILE_CURRENT);
        }
        setg(buffer_, buffer_, buffer_);
        return 0;
    }

public:
    bool open(const char* path) {
        close();
        handle_ = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if ( handle_ == INVALID_HANDLE_VALUE )
            return false;
        setg(buffer_, buffer_, buffer_);
        return true;
    }

    void close() {
        if ( handle_ != INVALID_HANDLE_VALUE ) {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
        setg(buffer_, buffer_, buffer_);
    }

    bool is_open() const { return handle_ != INVALID_HANDLE_VALUE; }

    ~WinShareDeleteBuf() { close(); }
};

InputFile::InputFile() : std::istream(nullptr), buf_(std::make_unique<WinShareDeleteBuf>()) { rdbuf(buf_.get()); }

InputFile::InputFile(const std::string& path, std::ios_base::openmode /*mode*/)
    : std::istream(nullptr), buf_(std::make_unique<WinShareDeleteBuf>()) {
    rdbuf(buf_.get());
    open(path);
}

InputFile::~InputFile() = default;

void InputFile::open(const std::string& path, std::ios_base::openmode /*mode*/) {
    if ( buf_->open(path.c_str()) )
        clear();
    else
        setstate(failbit);
}

bool InputFile::is_open() const { return buf_->is_open(); }

void InputFile::close() {
    buf_->close();
    clear();
}

FILE* fopen_with_share_delete(const char* path, const char* mode) {
    DWORD access = GENERIC_READ;
    DWORD creation = OPEN_EXISTING;

    HANDLE h = CreateFileA(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, creation,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if ( h == INVALID_HANDLE_VALUE )
        return nullptr;

    int fd = _open_osfhandle(reinterpret_cast<intptr_t>(h), _O_RDONLY);
    if ( fd == -1 ) {
        CloseHandle(h);
        return nullptr;
    }

    FILE* fp = _fdopen(fd, mode);
    if ( ! fp )
        _close(fd); // also closes the underlying handle

    return fp;
}

uint64_t reliable_inode(const char* path, uint64_t stat_ino) {
    HANDLE h = CreateFileA(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if ( h != INVALID_HANDLE_VALUE ) {
        BY_HANDLE_FILE_INFORMATION fi;
        if ( GetFileInformationByHandle(h, &fi) ) {
            CloseHandle(h);
            return (static_cast<uint64_t>(fi.nFileIndexHigh) << 32) | fi.nFileIndexLow;
        }
        CloseHandle(h);
    }
    return stat_ino;
}

} // namespace zeek::input::reader::detail

#else

#include <cstdio>

#include "zeek/input/InputFile.h"

namespace zeek::input::reader::detail {

FILE* fopen_with_share_delete(const char* path, const char* mode) { return fopen(path, mode); }

uint64_t reliable_inode(const char* path, uint64_t stat_ino) { return stat_ino; }

} // namespace zeek::input::reader::detail

#endif
