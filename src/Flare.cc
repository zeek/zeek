// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Flare.h"

#include <fcntl.h>
#include <unistd.h>
#include <cerrno>

#include "zeek/Reporter.h"

#ifdef _MSC_VER

#include <winsock2.h>

#define fatalError(...)                                                                                                \
    do {                                                                                                               \
        if ( reporter )                                                                                                \
            reporter->FatalError(__VA_ARGS__);                                                                         \
        else {                                                                                                         \
            fprintf(stderr, __VA_ARGS__);                                                                              \
            fprintf(stderr, "\n");                                                                                     \
            _exit(1);                                                                                                  \
        }                                                                                                              \
    } while ( 0 )

#endif

namespace zeek::detail {

Flare::Flare()
#ifndef _MSC_VER
    : pipe(FD_CLOEXEC, FD_CLOEXEC, O_NONBLOCK, O_NONBLOCK) {
}
#else
{
    WSADATA wsaData;
    if ( WSAStartup(MAKEWORD(2, 2), &wsaData) != 0 )
        fatalError("WSAStartup failure: %d", WSAGetLastError());

    recvfd = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if ( recvfd == (int)INVALID_SOCKET )
        fatalError("WSASocket failure: %d", WSAGetLastError());

    sendfd = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if ( sendfd == (int)INVALID_SOCKET )
        fatalError("WSASocket failure: %d", WSAGetLastError());

    sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr.s_addr);
    if ( bind(recvfd, (sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR )
        fatalError("bind failure: %d", WSAGetLastError());

    int salen = sizeof(sa);
    memset(&sa, 0, sizeof(sa));
    if ( getsockname(recvfd, (sockaddr*)&sa, &salen) == SOCKET_ERROR )
        fatalError("getsockname failure: %d", WSAGetLastError());

    if ( connect(sendfd, (sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR )
        fatalError("connect failure: %d", WSAGetLastError());
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

Flare::~Flare() {
#ifdef _MSC_VER
    // This needs to be called for every time WSAStartup is called in the constructor.
    WSACleanup();
#endif
}

void Flare::Fire(bool signal_safe) {
    char tmp = 0;

#ifndef _MSC_VER
    for ( ;; ) {
        int n = write(pipe.WriteFD(), &tmp, 1);
        if ( n > 0 )
            // Success -- wrote a byte to pipe.
            break;

        if ( n < 0 ) {
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
#else
    WSABUF data_buf;
    data_buf.len = 1;
    data_buf.buf = &tmp;

    WSAOVERLAPPED send_overlapped;
    SecureZeroMemory((PVOID)&send_overlapped, sizeof(WSAOVERLAPPED));

    send_overlapped.hEvent = WSACreateEvent();
    if ( send_overlapped.hEvent == NULL ) {
        bad_pipe_op(util::fmt("WSACreateEvent failed with error: %d\n", WSAGetLastError()), signal_safe);
        closesocket(recvfd);
        closesocket(sendfd);
        return;
    }

    DWORD sent_bytes;
    int err = 0;

    // Try to send data. Fail if we got a socket error but the error wasn't that data
    // is pending.
    int n = WSASend(sendfd, &data_buf, 1, &sent_bytes, 0, &send_overlapped, NULL);
    if ( (n == SOCKET_ERROR) && WSA_IO_PENDING != (err = WSAGetLastError()) ) {
        bad_pipe_op(util::fmt("WSASend failed: %d", err), signal_safe);
        return;
    }

    // Wait for the overlapped event to complete so that we're sure the data got sent.
    int rc = WSAWaitForMultipleEvents(1, &send_overlapped.hEvent, TRUE, INFINITE, TRUE);
    if ( rc == WSA_WAIT_FAILED ) {
        bad_pipe_op(util::fmt("WSAWaitForMultipleEvents(send) failed with error: %d", WSAGetLastError()), signal_safe);
        return;
    }

    DWORD flags;
    rc = WSAGetOverlappedResult(sendfd, &send_overlapped, &sent_bytes, FALSE, &flags);
    if ( rc == FALSE ) {
        bad_pipe_op(util::fmt("WSAGetOverlappedResult(send) failed with error: %d", WSAGetLastError()), signal_safe);
        return;
    }

    WSAResetEvent(send_overlapped.hEvent);
    WSACloseEvent(send_overlapped.hEvent);
#endif
}

int Flare::Extinguish(bool signal_safe) {
    int rval = 0;
    char tmp[256];

#ifndef _MSC_VER
    for ( ;; ) {
        int n = read(pipe.ReadFD(), &tmp, sizeof(tmp));
        if ( n >= 0 ) {
            rval += n;
            // Pipe may not be empty yet: try again.
            continue;
        }

        if ( errno == EAGAIN )
            // Success: pipe is now empty.
            break;

        if ( errno == EINTR )
            // Interrupted: try again.
            continue;

        bad_pipe_op("read", signal_safe);
    }
#else
    WSABUF data_buf;
    data_buf.len = 256;
    data_buf.buf = tmp;

    WSAOVERLAPPED recv_overlapped;
    SecureZeroMemory((PVOID)&recv_overlapped, sizeof(WSAOVERLAPPED));

    recv_overlapped.hEvent = WSACreateEvent();
    if ( recv_overlapped.hEvent == NULL ) {
        bad_pipe_op(util::fmt("WSACreateEvent(recv) failed with error: %d\n", WSAGetLastError()), signal_safe);
        closesocket(recvfd);
        closesocket(sendfd);
        return 0;
    }

    DWORD recv_bytes = 0;
    DWORD flags = 0;
    int err = 0;

    // Try to receive data. Fail if we got a socket error but the error wasn't that data
    // is pending.
    int n = WSARecv(recvfd, &data_buf, 1, &recv_bytes, &flags, &recv_overlapped, NULL);
    if ( (n == SOCKET_ERROR) && WSA_IO_PENDING != (err = WSAGetLastError()) ) {
        bad_pipe_op(util::fmt("WSARecv failed: %d", err), signal_safe);
        return 0;
    }

    // Wait for the overlapped event to complete so that we're sure the data got received.
    int rc = WSAWaitForMultipleEvents(1, &recv_overlapped.hEvent, TRUE, INFINITE, TRUE);
    if ( rc == WSA_WAIT_FAILED ) {
        bad_pipe_op(util::fmt("WSAWaitForMultipleEvents(recv) failed with error: %d", WSAGetLastError()), signal_safe);
        return 0;
    }

    rc = WSAGetOverlappedResult(recvfd, &recv_overlapped, &recv_bytes, FALSE, &flags);
    if ( rc == FALSE ) {
        bad_pipe_op(util::fmt("WSAGetOverlappedResult(recv) failed with error: %d", WSAGetLastError()), signal_safe);
        return 0;
    }

    rval = recv_bytes;

    WSAResetEvent(recv_overlapped.hEvent);
    WSACloseEvent(recv_overlapped.hEvent);
#endif

    return rval;
}

} // namespace zeek::detail
