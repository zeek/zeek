// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Flare.h"

#include <fcntl.h>
#include <unistd.h>
#include <cerrno>

#include "zeek/Reporter.h"

#ifdef _MSC_VER

#include <afunix.h>
#include <winsock2.h>
#include <atomic>
#include <filesystem>
#include <mutex>
#include <string>

#define fatalError(...)                                                                                                \
    do {                                                                                                               \
        if ( zeek::reporter )                                                                                          \
            zeek::reporter->FatalError(__VA_ARGS__);                                                                   \
        else {                                                                                                         \
            fprintf(stderr, __VA_ARGS__);                                                                              \
            fprintf(stderr, "\n");                                                                                     \
            _exit(1);                                                                                                  \
        }                                                                                                              \
    } while ( 0 )

static void EnsureWinsockInitialized() {
    static std::once_flag flag;
    std::call_once(flag, []() {
        WSADATA wsaData;
        if ( WSAStartup(MAKEWORD(2, 2), &wsaData) != 0 )
            fatalError("WSAStartup failure: %d", WSAGetLastError());
    });
}

static void SetNonBlocking(SOCKET fd) {
    u_long nonblocking = 1;
    if ( ioctlsocket(fd, FIONBIO, &nonblocking) == SOCKET_ERROR )
        fatalError("ioctlsocket failure: %d", WSAGetLastError());
}

static void CreateIpSocketPair(SOCKET socks[2]) {
    socks[0] =
        WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if ( socks[0] == INVALID_SOCKET )
        fatalError("WSASocket failure: %d", WSAGetLastError());
    socks[1] =
        WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if ( socks[1] == INVALID_SOCKET )
        fatalError("WSASocket failure: %d", WSAGetLastError());

    sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    if ( bind(socks[0], (sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR )
        fatalError("bind failure: %d", WSAGetLastError());
    int salen = sizeof(sa);
    if ( getsockname(socks[0], (sockaddr*)&sa, &salen) == SOCKET_ERROR )
        fatalError("getsockname failure: %d", WSAGetLastError());
    if ( connect(socks[1], (sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR )
        fatalError("connect failure: %d", WSAGetLastError());
}

static std::string GenerateUniqueSocketPath(const std::string& dir) {
    static std::atomic<uint64_t> counter{0};
    auto id = counter.fetch_add(1);
    // Keep filename short — sockaddr_un.sun_path is limited to 108 bytes.
    auto path = std::filesystem::path(dir) / ("zf" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(id));
    return path.string();
}

static void CreateUnixSocketPair(SOCKET socks[2], const std::string& socketDir) {
    socks[0] = socks[1] = INVALID_SOCKET;

    // Ensure the socket directory exists.
    std::filesystem::create_directories(socketDir);

    std::string socketPath = GenerateUniqueSocketPath(socketDir);

    if ( socketPath.size() >= sizeof(sockaddr_un::sun_path) )
        fatalError("CreateUnixSocketPair: socket path too long (%zu >= %zu): %s", socketPath.size(),
                   sizeof(sockaddr_un::sun_path), socketPath.c_str());

    // Clean up any stale socket file at this path.
    if ( std::filesystem::exists(socketPath) )
        std::filesystem::remove(socketPath);

    SOCKET listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if ( listener == INVALID_SOCKET )
        fatalError("CreateUnixSocketPair: socket() failure: %d", WSAGetLastError());

    sockaddr_un unixAddr;
    memset(&unixAddr, 0, sizeof(unixAddr));
    unixAddr.sun_family = AF_UNIX;
    strncpy_s(unixAddr.sun_path, socketPath.c_str(), sizeof(unixAddr.sun_path) - 1);
    socklen_t addrlen = sizeof(unixAddr);

    if ( bind(listener, (sockaddr*)&unixAddr, addrlen) == SOCKET_ERROR ) {
        int err = WSAGetLastError();
        closesocket(listener);
        fatalError("CreateUnixSocketPair: bind failure: %d, path: %s, exists: %s", err, socketPath.c_str(),
                   std::filesystem::exists(socketPath) ? "yes" : "no");
    }

    if ( listen(listener, 1) == SOCKET_ERROR ) {
        int err = WSAGetLastError();
        closesocket(listener);
        std::filesystem::remove(socketPath);
        fatalError("CreateUnixSocketPair: listen failure: %d", err);
    }

    socks[0] = WSASocket(AF_UNIX, SOCK_STREAM, 0, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if ( socks[0] == INVALID_SOCKET ) {
        int err = WSAGetLastError();
        closesocket(listener);
        std::filesystem::remove(socketPath);
        fatalError("CreateUnixSocketPair: WSASocket failure: %d", err);
    }

    if ( connect(socks[0], (sockaddr*)&unixAddr, addrlen) == SOCKET_ERROR ) {
        int err = WSAGetLastError();
        closesocket(socks[0]);
        closesocket(listener);
        std::filesystem::remove(socketPath);
        fatalError("CreateUnixSocketPair: connect failure: %d", err);
    }

    // Socket file no longer needed once connected.
    std::filesystem::remove(socketPath);

    socks[1] = accept(listener, nullptr, nullptr);
    closesocket(listener);
    if ( socks[1] == INVALID_SOCKET ) {
        int err = WSAGetLastError();
        closesocket(socks[0]);
        fatalError("CreateUnixSocketPair: accept failure: %d", err);
    }
}

// Returns the SOCKET_FILE_PATH env var value, or empty if not set.
// When set, this is used as a directory for AF_UNIX socket pairs instead of
// loopback UDP sockets.
static const std::string& GetSocketFileDir() {
    static std::string dir;
    static std::once_flag flag;
    std::call_once(flag, []() {
        const char* env = getenv("SOCKET_FILE_PATH");
        if ( env )
            dir = env;
    });
    return dir;
}

#endif

namespace zeek::detail {

Flare::Flare()
#ifndef _MSC_VER
    : pipe(FD_CLOEXEC, FD_CLOEXEC, O_NONBLOCK, O_NONBLOCK) {
}
#else
{
    EnsureWinsockInitialized();

    const auto& socketDir = GetSocketFileDir();
    SOCKET socks[2];

    if ( socketDir.empty() )
        CreateIpSocketPair(socks);
    else
        CreateUnixSocketPair(socks, socketDir);

    recvfd = static_cast<int>(socks[0]);
    sendfd = static_cast<int>(socks[1]);

    // Both ends must be non-blocking: recvfd so Extinguish() doesn't hang,
    // and sendfd so Fire() doesn't hang when the buffer is full.
    SetNonBlocking(socks[0]);
    SetNonBlocking(socks[1]);
}
#endif


[[noreturn]] static void bad_pipe_op(const char* which, bool signal_safe) {
    if ( signal_safe )
        abort();

    char buf[256];
    util::zeek_strerror_r(errno, buf, sizeof(buf));

    if ( reporter )
        reporter->FatalErrorWithCore("unexpected pipe %s failure: %s", which, buf);
    else {
        fprintf(stderr, "unexpected pipe %s failure: %s", which, buf);
        abort();
    }
}

void Flare::Fire(bool signal_safe) {
    char tmp = 0;

    for ( ;; ) {
#ifndef _MSC_VER
        int n = write(pipe.WriteFD(), &tmp, 1);

#else
        int n = send(sendfd, &tmp, 1, 0);
#endif
        if ( n > 0 )
            // Success -- wrote a byte to pipe.
            break;

        if ( n < 0 ) {
#ifdef _MSC_VER
            int wsa_err = WSAGetLastError();
            if ( wsa_err == WSAEWOULDBLOCK )
                // Success: buffer is full, at least one byte is already in it.
                break;
            errno = wsa_err;
            bad_pipe_op("send", signal_safe);
#endif
            if ( errno == EAGAIN )
                // Success: pipe is full and just need at least one byte in it.
                break;

            if ( errno == EINTR )
                // Interrupted: try again.
                continue;

            bad_pipe_op("write", signal_safe);
        }

        // No error, but didn't write a byte: try again.
    }
}

int Flare::Extinguish(bool signal_safe) {
    int rval = 0;
    char tmp[256];

    for ( ;; ) {
#ifndef _MSC_VER
        int n = read(pipe.ReadFD(), &tmp, sizeof(tmp));
#else
        int n = recv(recvfd, tmp, sizeof(tmp), 0);
#endif
        if ( n >= 0 ) {
            rval += n;
            // Pipe may not be empty yet: try again.
            continue;
        }
#ifdef _MSC_VER
        if ( WSAGetLastError() == WSAEWOULDBLOCK )
            break;
        errno = WSAGetLastError();
        bad_pipe_op("recv", signal_safe);
#endif
        if ( errno == EAGAIN )
            // Success: pipe is now empty.
            break;

        if ( errno == EINTR )
            // Interrupted: try again.
            continue;

        bad_pipe_op("read", signal_safe);
    }

    return rval;
}

} // namespace zeek::detail

#include <thread>

#include "zeek/3rdparty/doctest.h"

#ifdef _MSC_VER
#include <winsock2.h>
#else
#include <poll.h>
#endif

using zeek::detail::Flare;

// Wait for a Flare's FD to become readable, with a timeout in milliseconds.
// Returns true if the FD became ready, false on timeout.
static bool wait_for_flare(Flare& f, int timeout_ms) {
#ifdef _MSC_VER
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(static_cast<SOCKET>(f.FD()), &readfds);
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return select(0, &readfds, nullptr, nullptr, &tv) > 0;
#else
    struct pollfd pfd;
    pfd.fd = f.FD();
    pfd.events = POLLIN;
    return poll(&pfd, 1, timeout_ms) > 0;
#endif
}

TEST_SUITE_BEGIN("Flare");

TEST_CASE("flare fire and extinguish") {
    Flare f;
    f.Fire();
    int n = f.Extinguish();
    CHECK(n > 0);
}

TEST_CASE("flare extinguish without fire") {
    Flare f;
    int n = f.Extinguish();
    CHECK(n == 0);
}

TEST_CASE("flare cross-thread signaling") {
    Flare f;

    // Verify FD is not ready before Fire().
    CHECK_FALSE(wait_for_flare(f, 0));

    // Fire from another thread, then verify the FD becomes readable.
    std::thread t([&f]() { f.Fire(); });
    t.join();

    CHECK(wait_for_flare(f, 1000));
    int n = f.Extinguish();
    CHECK(n > 0);

    // After Extinguish, FD should no longer be ready.
    CHECK_FALSE(wait_for_flare(f, 0));
}

TEST_CASE("flare repeated cross-thread fire and extinguish") {
    Flare f;

    for ( int i = 0; i < 3; i++ ) {
        std::thread t([&f]() { f.Fire(); });
        t.join();

        CHECK(wait_for_flare(f, 1000));
        int n = f.Extinguish();
        CHECK(n > 0);
        CHECK_FALSE(wait_for_flare(f, 0));
    }
}

TEST_SUITE_END();
