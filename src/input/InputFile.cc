// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/input/InputFile.h"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#include <utility>
#else
#include <cstdio>
#endif

namespace zeek::input::reader::detail {

#ifdef _WIN32

namespace {

// Sharing flags that match POSIX semantics: allow concurrent reads, writes,
// and renames/deletes while the file is open.
constexpr DWORD share_all = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

// RAII wrapper for a Windows HANDLE.
struct UniqueHandle {
    HANDLE h = INVALID_HANDLE_VALUE;

    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE handle) : h(handle) {}
    ~UniqueHandle() { reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& o) noexcept : h(std::exchange(o.h, INVALID_HANDLE_VALUE)) {}
    UniqueHandle& operator=(UniqueHandle&& o) noexcept {
        if ( this != &o ) {
            reset();
            h = std::exchange(o.h, INVALID_HANDLE_VALUE);
        }
        return *this;
    }

    explicit operator bool() const { return h != INVALID_HANDLE_VALUE; }

    void reset() {
        if ( h != INVALID_HANDLE_VALUE ) {
            CloseHandle(h);
            h = INVALID_HANDLE_VALUE;
        }
    }

    HANDLE release() { return std::exchange(h, INVALID_HANDLE_VALUE); }
};

// Opens a file with share_all flags for the given access mode.
UniqueHandle open_shared(const char* path, DWORD access) {
    return UniqueHandle(CreateFileA(path, access, share_all, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
}

} // namespace

// A streambuf backed by a Windows HANDLE opened with FILE_SHARE_DELETE,
// allowing external renames while the file is open (matching POSIX semantics).
class WinShareDeleteBuf : public std::streambuf {
public:
    bool open(const char* path) {
        close();
        handle_ = open_shared(path, GENERIC_READ);
        if ( ! handle_ )
            return false;
        setg(buffer_, buffer_, buffer_);
        return true;
    }

    void close() {
        handle_.reset();
        setg(buffer_, buffer_, buffer_);
    }

    bool is_open() const { return static_cast<bool>(handle_); }

protected:
    int_type underflow() override {
        if ( gptr() < egptr() )
            return traits_type::to_int_type(*gptr());

        DWORD bytes_read = 0;
        if ( ! ReadFile(handle_.h, buffer_, BUF_SIZE, &bytes_read, nullptr) || bytes_read == 0 )
            return traits_type::eof();

        setg(buffer_, buffer_, buffer_ + bytes_read);
        return traits_type::to_int_type(*gptr());
    }

    int sync() override {
        // Seek back to account for unread buffered data so the next read
        // starts from the correct file position.
        if ( handle_ && gptr() < egptr() ) {
            LONG dist = -static_cast<LONG>(egptr() - gptr());
            SetFilePointer(handle_.h, dist, nullptr, FILE_CURRENT);
        }
        setg(buffer_, buffer_, buffer_);
        return 0;
    }

private:
    static constexpr size_t BUF_SIZE = 8192;
    UniqueHandle handle_;
    char buffer_[BUF_SIZE];
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
    auto handle = open_shared(path, GENERIC_READ);
    if ( ! handle )
        return nullptr;

    int fd = _open_osfhandle(reinterpret_cast<intptr_t>(handle.h), _O_RDONLY);
    if ( fd == -1 )
        return nullptr;

    // _open_osfhandle took ownership of the underlying Windows handle.
    handle.release();

    FILE* fp = _fdopen(fd, mode);
    if ( ! fp )
        _close(fd);

    return fp;
}

file_ino_t reliable_inode(const char* path, file_ino_t stat_ino) {
    auto handle = open_shared(path, FILE_READ_ATTRIBUTES);
    if ( ! handle )
        return stat_ino;

    BY_HANDLE_FILE_INFORMATION fi;
    if ( GetFileInformationByHandle(handle.h, &fi) )
        return (static_cast<uint64_t>(fi.nFileIndexHigh) << 32) | fi.nFileIndexLow;

    return stat_ino;
}

#else

FILE* fopen_with_share_delete(const char* path, const char* mode) { return fopen(path, mode); }

file_ino_t reliable_inode(const char* path, file_ino_t stat_ino) { return stat_ino; }

#endif

} // namespace zeek::input::reader::detail
