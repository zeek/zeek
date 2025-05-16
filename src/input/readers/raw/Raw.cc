// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/input/readers/raw/Raw.h"

#include <fcntl.h>
#ifndef _MSC_VER
#include <spawn.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>

extern char** environ;

#include "zeek/input/Component.h"
#include "zeek/input/readers/raw/Plugin.h"
#include "zeek/input/readers/raw/raw.bif.h"
#include "zeek/threading/SerialTypes.h"

extern "C" {
#include "zeek/3rdparty/setsignal.h"
}

using zeek::threading::Field;
using zeek::threading::Value;

namespace zeek::input::reader::detail {

const int Raw::block_size = 4096; // how big do we expect our chunks of data to be.

Raw::Raw(ReaderFrontend* frontend) : ReaderBackend(frontend), file(nullptr, fclose), stderrfile(nullptr, fclose) {
    execute = false;
    firstrun = true;
    mtime = 0;
    ino = 0;
    dev = 0;
    forcekill = false;
    offset = 0;
    separator.assign((const char*)BifConst::InputRaw::record_separator->Bytes(),
                     BifConst::InputRaw::record_separator->Len());

    sep_length = BifConst::InputRaw::record_separator->Len();

    bufpos = 0;
    bufsize = 0;

    stdin_fileno = fileno(stdin);
    stdout_fileno = fileno(stdout);
    stderr_fileno = fileno(stderr);

    childpid = -1;

    stdin_towrite = 0; // by default do not open stdin
    use_stderr = false;
}

Raw::~Raw() { DoClose(); }

void Raw::DoClose() {
    if ( file )
        CloseInput();

    if ( execute && childpid > 0 && kill(childpid, 0) == 0 ) {
        // Kill child process group.
        kill(-childpid, SIGTERM);

        if ( forcekill ) {
            usleep(200); // 200 msecs should be enough for anyone ;)

            if ( kill(childpid, 0) == 0 ) // perhaps it is already gone
                kill(-childpid, SIGKILL);
        }
    }
}

void Raw::ClosePipeEnd(int i) {
    if ( pipes[i] == -1 )
        return;

    util::safe_close(pipes[i]);
    pipes[i] = -1;
}

bool Raw::SetFDFlags(int fd, int cmd, int flags) {
    if ( fcntl(fd, cmd, flags) != -1 )
        return true;

    char buf[256];
    util::zeek_strerror_r(errno, buf, sizeof(buf));
    Error(Fmt("failed to set fd flags: %s", buf));
    return false;
}

std::unique_lock<std::mutex> Raw::AcquireForkMutex() {
    auto lock = plugin::detail::Zeek_RawReader::plugin.ForkMutex();

    try {
        lock.lock();
    }

    catch ( const std::system_error& e ) {
        reporter->FatalErrorWithCore("cannot lock fork mutex: %s", e.what());
    }

    return lock;
}

bool Raw::Execute() {
#ifdef _MSC_VER
    // Executing applications is currently not supported on Windows
    return false;
#else
    // AFAICT, pipe/fork/exec should be thread-safe, but actually having
    // multiple threads set up pipes and fork concurrently sometimes
    // results in problems w/ a stdin pipe not ever getting an EOF even
    // though both ends of it are closed.  But if the same threads
    // allocate pipes and fork individually or sequentially, that issue
    // never crops up... ("never" meaning I haven't seen in it in
    // hundreds of tests using 50+ threads where before I'd see the issue
    // w/ just 2 threads ~33% of the time).
    auto lock = AcquireForkMutex();

    if ( pipe(pipes) != 0 || pipe(pipes + 2) || pipe(pipes + 4) ) {
        Error(Fmt("Could not open pipe: %d", errno));
        return false;
    }

    short spawn_flags = 0;
    // equivalent to setpgid(0,0) in the child
    spawn_flags |= POSIX_SPAWN_SETPGROUP;

    posix_spawn_file_actions_t actions;
    if ( posix_spawn_file_actions_init(&actions) != 0 ) {
        Error(Fmt("Could not call posix_spawn_file_actions_init: %d", errno));
        return false;
    }

    auto file_actions_res = posix_spawn_file_actions_addclose(&actions, pipes[stdout_in]);
    file_actions_res |= posix_spawn_file_actions_adddup2(&actions, pipes[stdout_out], stdout_fileno);
    file_actions_res |= posix_spawn_file_actions_addclose(&actions, pipes[stdout_out]);
    file_actions_res |= posix_spawn_file_actions_addclose(&actions, pipes[stdin_out]);
    file_actions_res |= posix_spawn_file_actions_adddup2(&actions, pipes[stdin_in], stdin_fileno);
    file_actions_res |= posix_spawn_file_actions_addclose(&actions, pipes[stdin_in]);
    file_actions_res |= posix_spawn_file_actions_addclose(&actions, pipes[stderr_in]);
    file_actions_res |= posix_spawn_file_actions_adddup2(&actions, pipes[stderr_out], stderr_fileno);
    file_actions_res |= posix_spawn_file_actions_addclose(&actions, pipes[stderr_out]);

    if ( file_actions_res != 0 ) {
        Error("Error during posix_spawn_file_actions_add");
        posix_spawn_file_actions_destroy(&actions);
        return false;
    }

    posix_spawnattr_t attrs;
    if ( posix_spawnattr_init(&attrs) != 0 ) {
        Error(Fmt("Could not call posix_spawnattr_init: %d", errno));
        posix_spawn_file_actions_destroy(&actions);
        return false;
    }

    // this can only fail with EINVAL - and we don't care too much about this.
    posix_spawnattr_setflags(&attrs, spawn_flags);

    // Signal mask is inherited, so reset any ignored
    // signals to default behavior and unblock any blocked signals.
    // The old code in the child process calls SIG_UNBLOCK on a full mask,
    // and set SIGPIPE to the default signal, ignoring anything else. New
    // code replicates this behavior.
    sigset_t mask;
    sigemptyset(&mask);
    spawn_flags |= POSIX_SPAWN_SETSIGMASK;
    // this can only fail with EINVAL - which is not fatal
    posix_spawnattr_setsigmask(&attrs, &mask);

    spawn_flags |= POSIX_SPAWN_SETSIGDEF;
    sigset_t sigdefault;
    sigemptyset(&sigdefault);
    sigaddset(&sigdefault, SIGPIPE);
    // this can only fail with EINVAL - which is not fatal
    posix_spawnattr_setsigdefault(&attrs, &sigdefault);

    const char* spawn_argv[] = {"sh", "-c", fname.c_str(), nullptr};
    auto posix_spawn_res = posix_spawn(&childpid, "/bin/sh", &actions, &attrs, const_cast<char**>(spawn_argv), environ);

    posix_spawnattr_destroy(&attrs);
    posix_spawn_file_actions_destroy(&actions);

    if ( posix_spawn_res != 0 ) {
        Error(Fmt("Could not spawn child process: %d", errno));
        return false;
    }

    lock.unlock();

    ClosePipeEnd(stdout_out);

    if ( Info().mode == MODE_STREAM ) {
        if ( ! SetFDFlags(pipes[stdout_in], F_SETFL, O_NONBLOCK) )
            return false;
    }

    ClosePipeEnd(stdin_in);

    if ( stdin_towrite ) {
        // Ya, just always set this to nonblocking. We do not
        // want to block on a program receiving data. Note
        // that there is a small gotcha with it. More data is
        // queued when more data is read from the program
        // output. Hence, when having a program in
        // mode_manual where the first write cannot write
        // everything, the rest will be stuck in a queue that
        // is never emptied.
        if ( ! SetFDFlags(pipes[stdin_out], F_SETFL, O_NONBLOCK) )
            return false;
    }
    else
        ClosePipeEnd(stdin_out);

    ClosePipeEnd(stderr_out);

    if ( use_stderr ) {
        if ( ! SetFDFlags(pipes[stderr_in], F_SETFL, O_NONBLOCK) )
            return false;
    }
    else
        ClosePipeEnd(stderr_in);

    file = std::unique_ptr<FILE, int (*)(FILE*)>(fdopen(pipes[stdout_in], "r"), fclose);

    if ( ! file ) {
        Error("Could not convert stdout_in fileno to file");
        return false;
    }

    pipes[stdout_in] = -1; // will be closed by fclose

    if ( use_stderr ) {
        stderrfile = std::unique_ptr<FILE, int (*)(FILE*)>(fdopen(pipes[stderr_in], "r"), fclose);

        if ( ! stderrfile ) {
            Error("Could not convert stderr_in fileno to file");
            return false;
        }

        pipes[stderr_in] = -1; // will be closed by fclose
    }

    return true;
#endif
}

bool Raw::OpenInput() {
    if ( execute )
        return Execute();

    else {
        file = std::unique_ptr<FILE, int (*)(FILE*)>(fopen(fname.c_str(), "r"), fclose);
        if ( ! file ) {
            if ( Info().mode == MODE_STREAM )
                // Wait for file to appear
                return true;

            Error(Fmt("Init: cannot open %s", fname.c_str()));
            return false;
        }

        if ( Info().mode == MODE_STREAM || Info().mode == MODE_REREAD ) {
            struct stat sb;
            if ( fstat(fileno(file.get()), &sb) == -1 ) {
                // This is unlikely to fail
                Error(Fmt("Could not get fstat for %s", fname.c_str()));
                return false;
            }

            mtime = sb.st_mtime;
            ino = sb.st_ino;
            dev = sb.st_dev;
        }

        if ( ! SetFDFlags(fileno(file.get()), F_SETFD, FD_CLOEXEC) )
            Warning(Fmt("Init: cannot set close-on-exec for %s", fname.c_str()));
    }

    if ( offset ) {
        int whence = (offset >= 0) ? SEEK_SET : SEEK_END;
        int64_t pos = (offset >= 0) ? offset : offset + 1; // we want -1 to be the end of the file

        if ( fseek(file.get(), pos, whence) < 0 ) {
            char buf[256];
            util::zeek_strerror_r(errno, buf, sizeof(buf));
            Error(Fmt("Seek failed in init: %s", buf));
        }
    }

    return true;
}

bool Raw::CloseInput() {
    if ( ! file ) {
        InternalWarning(Fmt("Trying to close closed file for stream %s", fname.c_str()));
        return false;
    }
#ifdef DEBUG
    Debug(DBG_INPUT, "Raw reader starting close");
#endif

    file.reset(nullptr);

    if ( use_stderr )
        stderrfile.reset(nullptr);

    if ( execute ) {
        for ( int i = 0; i < 6; i++ )
            ClosePipeEnd(i);
    }

#ifdef DEBUG
    Debug(DBG_INPUT, "Raw reader finished close");
#endif

    return true;
}

bool Raw::DoInit(const ReaderInfo& info, int num_fields, const Field* const* fields) {
    if ( ! info.source || strlen(info.source) == 0 ) {
        Error("No source path provided");
        return false;
    }

    fname = info.source;
    mtime = 0;
    ino = 0;
    dev = 0;
    execute = false;
    firstrun = true;
    int want_fields = 1;
    bool result;

    std::string source = std::string(info.source);
    char last = info.source[source.length() - 1];
    if ( last == '|' ) {
        execute = true;
        fname = source.substr(0, fname.length() - 1);
    }

    ReaderInfo::config_map::const_iterator it = info.config.find("stdin"); // data that is sent to the child process
    if ( it != info.config.end() ) {
        stdin_string = it->second;
        stdin_towrite = stdin_string.length();
    }

    it = info.config.find("read_stderr"); // we want to read stderr
    if ( it != info.config.end() && execute ) {
        use_stderr = true;
        want_fields = 2;
    }

    it = info.config.find("force_kill"); // we want to be sure that our child is dead when we exit
    if ( it != info.config.end() && execute ) {
        forcekill = true;
    }

    it = info.config.find("offset"); // we want to seek to a given offset inside the file
    if ( it != info.config.end() && ! execute && (Info().mode == MODE_STREAM || Info().mode == MODE_MANUAL) ) {
        std::string offset_s = it->second;
        offset = strtoll(offset_s.c_str(), nullptr, 10);
    }
    else if ( it != info.config.end() ) {
        Error(
            "Offset only is supported for MODE_STREAM and MODE_MANUAL; it is also not supported "
            "when executing a command");
        return false;
    }

    if ( num_fields != want_fields ) {
        Error(
            Fmt("Filter for raw reader contains wrong number of fields -- got %d, expected %d. "
                "Filters for the raw reader contain one string field when used in normal mode and "
                "one string and one bool fields when using execute mode with stderr capturing. "
                "Filter ignored.",
                num_fields, want_fields));
        return false;
    }

    if ( fields[0]->type != TYPE_STRING ) {
        Error("First field for raw reader always has to be of type string.");
        return false;
    }
    if ( use_stderr && fields[1]->type != TYPE_BOOL ) {
        Error("Second field for raw reader always has to be of type bool.");
        return false;
    }

    if ( execute && Info().mode == MODE_REREAD ) {
        // for execs this makes no sense - would have to execute each heartbeat?
        Error("Rereading only supported for files, not for executables.");
        return false;
    }

    result = OpenInput();

    if ( result == false )
        return result;

#ifdef DEBUG
    Debug(DBG_INPUT, "Raw reader created, will perform first update");
#endif

    // after initialization - do update
    DoUpdate();

#ifdef DEBUG
    Debug(DBG_INPUT, "First update went through");
#endif
    return true;
}

int64_t Raw::GetLine(FILE* arg_file) {
    errno = 0;

    if ( ! buf ) {
        buf = std::unique_ptr<char[]>(new char[block_size]);
        bufpos = 0;
        bufsize = block_size;
    }

    for ( ;; ) {
        size_t readbytes = fread(buf.get() + bufpos, 1, bufsize - bufpos, arg_file);

        bufpos = bufpos + readbytes;

        // Nothing in the buffer and errno set, yield.
        if ( bufpos == 0 && errno != 0 )
            break;

        // researching everything each time is a bit... cpu-intensive. But otherwise we have
        // to deal with situations where the separator is multi-character and split over multiple
        // reads...
        //
        // memmem() would be more appropriate, but not available on Windows.
        int found = util::strstr_n(bufpos, reinterpret_cast<u_char*>(buf.get()), separator.size(),
                                   reinterpret_cast<const u_char*>(separator.c_str()));

        if ( found == -1 ) {
            // we did not find it and have to search again in the next try.
            // but first check if we encountered the file end - because if we did this was it.
            if ( feof(arg_file) != 0 ) {
                if ( bufpos == 0 )
                    return -1; // signal EOF - and that we had no more data.
                else {
                    outbuf = std::move(buf); // buf is null after this
                    return bufpos;           // flush out remaining buffered data as line
                }
            }

            // No separator found and buffer full, realloc and retry reading more right away.
            if ( bufpos == bufsize ) {
                std::unique_ptr<char[]> newbuf = std::unique_ptr<char[]>(new char[bufsize + block_size]);
                memcpy(newbuf.get(), buf.get(), bufsize);
                buf = std::move(newbuf);
                bufsize = bufsize + block_size;
            }
            else {
                // Short or empty read, some data in the buffer, but no separator found
                // and also not EOF: This is likely reading from a pipe where the separator
                // wasn't yet produced. Yield to retry on the next heartbeat.
                return -2;
            }
        }
        else {
            size_t sep_idx = static_cast<size_t>(found);
            assert(sep_idx <= bufsize - sep_length);
            size_t remaining = bufpos - sep_idx - sep_length;

            outbuf = std::move(buf);

            if ( remaining > 0 ) {
                // we have leftovers. copy them into the buffer for the next line
                assert(remaining <= block_size);
                buf = std::unique_ptr<char[]>(new char[block_size]);
                bufpos = remaining;
                bufsize = block_size;

                memcpy(buf.get(), outbuf.get() + sep_idx + sep_length, remaining);
            }

            return sep_idx;
        }
    }

    if ( errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR )
        return -2;

    else {
        // an error code we did no expect. This probably is bad.
        Error(Fmt("Reader encountered unexpected error code %d", errno));
        return -3;
    }
}

// write to the stdin of the child process
void Raw::WriteToStdin() {
    assert(stdin_towrite <= stdin_string.length());
    uint64_t pos = stdin_string.length() - stdin_towrite;

    errno = 0;
    ssize_t written = write(pipes[stdin_out], stdin_string.c_str() + pos, stdin_towrite);
    stdin_towrite -= written;

    if ( errno != 0 && errno != EAGAIN && errno != EWOULDBLOCK ) {
        Error(Fmt("Writing to child process stdin failed: %d. Stopping writing at position %" PRIu64, errno, pos));
        stdin_towrite = 0;
    }

    if ( stdin_towrite == 0 ) // send EOF when we are done.
        ClosePipeEnd(stdin_out);

    if ( Info().mode == MODE_MANUAL && stdin_towrite != 0 ) {
        Error(
            Fmt("Could not write whole string to stdin of child process in one go. Please use "
                "STREAM mode to pass more data to child."));
    }
}

// read the entire file and send appropriate thingies back to InputMgr
bool Raw::DoUpdate() {
    if ( firstrun )
        firstrun = false;

    else {
        switch ( Info().mode ) {
            case MODE_REREAD: {
                assert(childpid == -1); // mode may not be used to execute child programs
                // check if the file has changed
                struct stat sb;
                if ( stat(fname.c_str(), &sb) == -1 ) {
                    Error(Fmt("Could not get stat for %s", fname.c_str()));
                    return false;
                }

                if ( sb.st_dev == dev && sb.st_ino == ino && sb.st_mtime == mtime )
                    // no change
                    return true;

                mtime = sb.st_mtime;
                ino = sb.st_ino;
                dev = sb.st_dev;
                // file changed. reread.
                //
                // fallthrough
            }

            case MODE_MANUAL:
                CloseInput();
                if ( ! OpenInput() )
                    return false;

                break;

            case MODE_STREAM:
                // Clear possible EOF condition
                if ( file )
                    clearerr(file.get());

                // Done if reading from a pipe
                if ( execute )
                    break;

                // Check if the file has changed
                struct stat sb;
                if ( stat(fname.c_str(), &sb) == -1 )
                    // File was removed
                    break;

                // Is it the same file?
                if ( file && sb.st_ino == ino && sb.st_dev == dev )
                    break;

                // File was replaced
                FILE* tfile;
                tfile = fopen(fname.c_str(), "r");
                if ( ! tfile )
                    break;

                // Stat newly opened file
                if ( fstat(fileno(tfile), &sb) == -1 ) {
                    // This is unlikely to fail
                    Error(Fmt("Could not fstat %s", fname.c_str()));
                    fclose(tfile);
                    return false;
                }
                if ( file )
                    file.reset(nullptr);
                file = std::unique_ptr<FILE, int (*)(FILE*)>(tfile, fclose);
                ino = sb.st_ino;
                dev = sb.st_dev;
                offset = 0;
                bufpos = 0;
                break;

            default: assert(false);
        }
    }

    assert((NumFields() == 1 && ! use_stderr) || (NumFields() == 2 && use_stderr));
    for ( ;; ) {
        if ( stdin_towrite > 0 )
            WriteToStdin();

        if ( ! file && Info().mode == MODE_STREAM )
            // Wait for file to appear
            break;

        int64_t length = GetLine(file.get());
        // printf("Read %lld bytes\n", length);

        if ( length == -3 )
            return false;

        else if ( length == -2 || length == -1 )
            // no data ready or eof
            break;

        Value** fields = new Value*[2]; // just always reserve 2. This means that our [] is too long
                                        // by a count of 1 if not using stderr. But who cares...

        // filter has exactly one text field. convert to it.
        Value* val = new Value(TYPE_STRING, true);
        val->val.string_val.data = outbuf.release();
        val->val.string_val.length = length;
        fields[0] = val;

        if ( use_stderr ) {
            Value* bval = new Value(TYPE_BOOL, true);
            bval->val.int_val = 0;
            fields[1] = bval;
        }

        Put(fields);
    }

    if ( use_stderr ) {
        for ( ;; ) {
            int64_t length = GetLine(stderrfile.get());
            // printf("Read stderr %lld bytes\n", length);
            if ( length == -3 )
                return false;

            else if ( length == -2 || length == -1 )
                break;

            Value** fields = new Value*[2];
            Value* val = new Value(TYPE_STRING, true);
            val->val.string_val.data = outbuf.release();
            val->val.string_val.length = length;
            fields[0] = val;
            Value* bval = new Value(TYPE_BOOL, true);
            bval->val.int_val = 1; // yes, we are stderr
            fields[1] = bval;

            Put(fields);
        }
    }

    if ( (Info().mode == MODE_MANUAL) || (Info().mode == MODE_REREAD) )
        // done with the current data source
        EndCurrentSend();

    // and let's check if the child process is still alive
    int return_code;
    if ( childpid != -1 && waitpid(childpid, &return_code, WNOHANG) != 0 ) {
        // child died
        childpid = -1;
        bool signal = false;
        int code = 0;
        if ( WIFEXITED(return_code) ) {
            code = WEXITSTATUS(return_code);
            if ( code != 0 )
                Error(Fmt("Child process exited with non-zero return code %d", code));
        }

        else if ( WIFSIGNALED(return_code) ) {
            signal = true;
            code = WTERMSIG(return_code);
            Error(Fmt("Child process exited due to signal %d", code));
        }

        else
            assert(false);

        Value** vals = new Value*[4];
        vals[0] = new Value(TYPE_STRING, true);
        auto val0_len = strlen(Info().name);
        vals[0]->val.string_val.data = util::copy_string(Info().name, val0_len);
        vals[0]->val.string_val.length = val0_len;
        vals[1] = new Value(TYPE_STRING, true);
        auto val1_len = strlen(Info().source);
        vals[1]->val.string_val.data = util::copy_string(Info().source, val1_len);
        vals[1]->val.string_val.length = val1_len;
        vals[2] = new Value(TYPE_COUNT, true);
        vals[2]->val.int_val = code;
        vals[3] = new Value(TYPE_BOOL, true);
        vals[3]->val.int_val = signal;

        // and in this case we can signal end_of_data even for the streaming reader
        if ( Info().mode == MODE_STREAM )
            EndCurrentSend();

        SendEvent("InputRaw::process_finished", 4, vals);
        return false;
    }

#ifdef DEBUG
    Debug(DBG_INPUT, "DoUpdate finished successfully");
#endif

    return true;
}

bool Raw::DoHeartbeat(double network_time, double current_time) {
    switch ( Info().mode ) {
        case MODE_MANUAL:
            // yay, we do nothing :)
            break;

        case MODE_REREAD:
        case MODE_STREAM:
#ifdef DEBUG
            Debug(DBG_INPUT, "Starting Heartbeat update");
#endif
            Update(); // call update and not DoUpdate, because update
                      // checks disabled.
#ifdef DEBUG
            Debug(DBG_INPUT, "Finished with heartbeat update");
#endif
            break;
        default: assert(false);
    }

    return true;
}

} // namespace zeek::input::reader::detail
