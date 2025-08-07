// See the file "COPYING" in the main distribution directory for copyright.

#define _XOPEN_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

constexpr auto ZEEK_ARCHIVER_VERSION = "v0.50-174";

struct Options {
    std::string src_dir;
    std::string dst_dir;

    bool verbose = false;
    bool oneshot = false;
    std::string delimiter = "__";
    std::string compress_ext = "gz";
    std::string compress_cmd = "gzip";
    std::string timestamp_fmt = "%Y-%m-%d-%H-%M-%S";
    std::vector<std::string> zip_file_extensions = {"gz", "bz2", "lz", "lz4"};

    int idle_poll_interval = 30;
};

static Options options;

struct LogFile {
    std::string path;
    std::string name;
    struct tm open;
    struct tm close;
    std::string ext;
    std::string suffix;

    std::string DestDir() const {
        char buf[64];
        auto res = strftime(buf, sizeof(buf), "%Y-%m-%d", &open);

        if ( res == 0 )
            return {};

        return buf;
    }

    std::string DestFile() const {
        constexpr auto time_fmt = "%H:%M:%S";
        char buf[64];
        auto res = strftime(buf, sizeof(buf), time_fmt, &open);

        if ( res == 0 )
            return {};

        std::string start = buf;

        res = strftime(buf, sizeof(buf), time_fmt, &close);

        if ( res == 0 )
            return {};

        std::string close = buf;

        std::string r = name + "." + start + "-" + close;
        if ( ! suffix.empty() )
            r += "-" + suffix;

        return r + ext;
    }
};

static double now() {
    struct timeval tv;

    if ( gettimeofday(&tv, 0) < 0 )
        return 0;

    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

static void debug(const char* format, ...) __attribute__((format(printf, 1, 2)));
static void debug(const char* format, ...) {
    if ( ! options.verbose )
        return;

    auto f = stdout;
    fprintf(f, "[%17.06f] [DEBUG] ", now());

    va_list args;
    va_start(args, format);
    vfprintf(f, format, args);
    va_end(args);

    fprintf(f, "\n");
}

static void info(const char* format, ...) __attribute__((format(printf, 1, 2)));
static void info(const char* format, ...) {
    auto f = stdout;
    fprintf(f, "[%17.06f] [INFO] ", now());

    va_list args;
    va_start(args, format);
    vfprintf(f, format, args);
    va_end(args);

    fprintf(f, "\n");
}

static void error(const char* format, ...) __attribute__((format(printf, 1, 2)));
static void error(const char* format, ...) {
    auto f = stderr;
    fprintf(f, "[%17.06f] [ERROR] ", now());

    va_list args;
    va_start(args, format);
    vfprintf(f, format, args);
    va_end(args);

    fprintf(f, "\n");
}

static void fatal(const char* format, ...) __attribute__((format(printf, 1, 2)));
static void fatal(const char* format, ...) {
    auto f = stderr;
    fprintf(f, "[%17.06f] [FATAL] ", now());

    va_list args;
    va_start(args, format);
    vfprintf(f, format, args);
    va_end(args);

    fprintf(f, "\n");
    exit(1);
}

static void print_version(FILE* f) { fprintf(f, "zeek-archiver %s\n", ZEEK_ARCHIVER_VERSION); }

static void print_usage() {
    print_version(stderr);
    fprintf(stderr, "usage: zeek-archiver [options] <src_dir> <dst_dir>\n");
    fprintf(stderr, "    <src_dir>                     | A directory to monitor for Zeek log files\n");
    fprintf(stderr, "    <dst_dir>                     | A directory to archive Zeek logs into\n");
    fprintf(stderr, "    --version                     | Print version and exit\n");
    fprintf(stderr, "    -1                            | Archive current logs and exit w/o looping\n");
    fprintf(stderr, "    -h|--help                     | Show this usage information\n");
    fprintf(stderr, "    -v|--verbose                  | Print verbose/debug logs to stderr\n");
    fprintf(stderr,
            "    -c|--compress <ext,cmd>       | File extension and compression command,\n"
            "                                    empty string means \"disable compression\"\n"
            "                                    (default: \"gz,gzip\")\n");
    fprintf(stderr,
            "    -d|--delimiter <string>       | Delimiter between timestamps in log names\n"
            "                                    (default: \"__\")\n");
    fprintf(stderr,
            "    -t|--time-fmt <string>        | Format of timestamps within input file names\n"
            "                                    (default: \"%%Y-%%m-%%d-%%H-%%M-%%S\")\n");
    fprintf(stderr,
            "    -z|--zip-extensions <strings> | File extensions for already-zipped logs,\n"
            "                                    an empty string disables this feature\n"
            "                                    (default: \"gz,bz2,lz,lz4\")\n");
}

static void usage_error(const char* format, ...) __attribute__((format(printf, 1, 2)));
static void usage_error(const char* format, ...) {
    print_usage();

    fprintf(stderr, "ERROR: ");

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    fprintf(stderr, "\n");

    exit(1);
}

static std::vector<std::string> split_string(std::string_view input, std::string_view delim) {
    std::vector<std::string> rval;
    size_t pos = 0;
    size_t n = 0;

    while ( (n = input.find(delim, pos)) != std::string::npos ) {
        rval.emplace_back(input.substr(pos, n - pos));
        pos = n + delim.size();
    }

    rval.emplace_back(input.substr(pos));
    return rval;
}

static std::string strip_string(std::string s) {
    auto notspace = [](unsigned char c) { return ! std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notspace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notspace).base(), s.end());
    return s;
}

static void consume_option_value(const std::string& flag, std::string arg_value) {
    if ( flag == "-c" || flag == "--compress" ) {
        if ( arg_value.empty() )
            options.compress_cmd = "";
        else {
            auto parts = split_string(arg_value, ",");

            if ( parts.size() != 2 )
                usage_error(
                    "--compress must give a 'ext,compress_cmd' formatted "
                    "value, got: %s",
                    arg_value.data());

            options.compress_ext = parts[0];
            options.compress_cmd = parts[1];
        }
    }


    else if ( flag == "-d" || flag == "--delimiter" ) {
        if ( arg_value.empty() )
            usage_error("flag '%s' is missing a value", flag.data());

        options.delimiter = std::move(arg_value);
    }

    else if ( flag == "-t" || flag == "--time-fmt" ) {
        if ( arg_value.empty() )
            usage_error("flag '%s' is missing a value", flag.data());

        options.timestamp_fmt = std::move(arg_value);
    }

    else if ( flag == "-z" || flag == "--zip-extensions" ) {
        options.zip_file_extensions = split_string(arg_value, ",");
    }
}

static void parse_options(int argc, char** argv) {
    std::set<std::string> flags = {
        "--version",  "-1", "-h",          "--help", "-v",         "--verbose", "-c",
        "--compress", "-d", "--delimiter", "-t",     "--time-fmt", "-z",        "--zip-extensions",
    };

    bool in_options = true;

    for ( auto i = 1; i < argc; ++i ) {
        auto arg = argv[i];

        if ( ! arg[0] )
            continue;

        if ( arg[0] == '-' ) {
            if ( ! in_options )
                usage_error(
                    "optional flags must precede non-optional arguments: "
                    "'%s'",
                    arg);

            if ( ! arg[1] )
                // Has to be something after a '-'
                usage_error("invalid argument: '%s'", arg);

            if ( arg[1] != '-' && arg[2] && arg[2] != '=' )
                // Invalid short flag: must be -x, -x v, or -x=v
                usage_error("invalid argument: '%s'", arg);

            std::string flag = arg;
            std::string opt_value;

            auto it = flag.find('=');

            if ( it == std::string::npos ) {
                if ( i + 1 < argc )
                    opt_value = argv[i + 1];
            }
            else {
                opt_value = flag.substr(it + 1);
                flag = flag.substr(0, it);
            }

            if ( flags.find(flag) == flags.end() )
                usage_error("invalid argument: '%s'", arg);

            if ( flag == "-1" ) {
                if ( ! opt_value.empty() && it != std::string::npos )
                    usage_error("invalid argument=value: '%s'", arg);

                options.oneshot = true;
                continue;
            }

            if ( flag == "--version" ) {
                if ( ! opt_value.empty() && it != std::string::npos )
                    usage_error("invalid argument=value: '%s'", arg);

                print_version(stdout);
                exit(0);
            }

            if ( flag == "-h" || flag == "--help" ) {
                if ( ! opt_value.empty() && it != std::string::npos )
                    usage_error("invalid argument=value: '%s'", arg);

                print_usage();
                exit(0);
            }

            if ( flag == "-v" || flag == "--verbose" ) {
                if ( ! opt_value.empty() && it != std::string::npos )
                    usage_error("invalid argument=value: '%s'", arg);

                options.verbose = true;
                continue;
            }

            if ( it == std::string::npos )
                ++i;

            consume_option_value(flag, std::move(opt_value));
            continue;
        }
        else {
            if ( options.src_dir.empty() ) {
                in_options = false;
                options.src_dir = arg;
            }
            else if ( options.dst_dir.empty() ) {
                in_options = false;
                options.dst_dir = arg;
            }
            else
                usage_error(
                    "extra/invalid argument: '%s': <src_dir>/<dst_dir> "
                    "already provided: %s/%s",
                    arg, options.src_dir.data(), options.dst_dir.data());
        }
    }

    if ( options.src_dir.empty() )
        usage_error("no <src_dir> provided");

    if ( options.dst_dir.empty() )
        usage_error("no <dst_dir> provided");
}

static bool make_dir(const char* dir) {
    if ( mkdir(dir, 0775) == 0 )
        return true;

    auto mkdir_errno = errno;
    struct stat st;

    if ( stat(dir, &st) == -1 ) {
        // Show the original failure reason for mkdir() since nothing's there
        // or we can't even tell what is now.
        error("Failed to create directory %s: %s", dir, strerror(mkdir_errno));
        return false;
    }

    if ( S_ISDIR(st.st_mode) )
        return true;

    error("Failed to create directory %s: exists but is not a directory", dir);
    return false;
}

static bool make_dirs(std::string_view dir) {
    auto parts = split_string(dir, "/");
    std::string current_dir = dir[0] == '/' ? "/" : "";
    std::vector<std::string> dirs;

    for ( auto& p : parts )
        if ( ! p.empty() )
            dirs.emplace_back(std::move(p));

    for ( size_t i = 0; i < dirs.size(); ++i ) {
        if ( i > 0 )
            current_dir += '/';

        current_dir += dirs[i];

        if ( ! make_dir(current_dir.data()) )
            return false;
    }

    return true;
}

bool is_file(const char* path) {
    struct stat st;

    if ( stat(path, &st) == -1 ) {
        if ( errno != ENOENT )
            error("can't stat %s: %s", path, strerror(errno));

        return false;
    }

    return S_ISREG(st.st_mode);
}

std::optional<bool> same_filesystem(const char* path1, const char* path2) {
    struct stat st1;
    struct stat st2;

    if ( stat(path1, &st1) == -1 ) {
        error("can't stat %s: %s", path1, strerror(errno));
        return {};
    }

    if ( stat(path2, &st2) == -1 ) {
        error("can't stat %s: %s", path2, strerror(errno));
        return {};
    }

    return st1.st_dev == st2.st_dev;
}

static bool ends_with(std::string_view s, std::string_view ending) {
    if ( ending.size() > s.size() )
        return false;

    return std::equal(ending.rbegin(), ending.rend(), s.rbegin());
}

static bool already_zipped(std::string_view file) {
    for ( const auto& e : options.zip_file_extensions )
        if ( ends_with(file, e) )
            return true;

    return false;
}

static pid_t child_pid = -1;

static void signal_handler(int signal) {
    if ( child_pid > 0 ) {
        kill(child_pid, SIGKILL);
        int status;
        waitpid(child_pid, &status, 0);
    }

    _exit(131);
}

// Fork a child and associate its stdin/stdout with the src and dst files,
// then run compress_cmd via system().
static int run_compress_cmd(const char* src_file, const char* dst_file) {
    child_pid = fork();

    if ( child_pid == -1 ) {
        error("Failed to fork() to run compress command: %s", strerror(errno));
        return -1;
    }

    if ( child_pid == 0 ) {
        int src_fd = open(src_file, O_RDONLY);

        if ( src_fd < 0 ) {
            error("Failed to open src_file %s: %s", src_file, strerror(errno));
            exit(254);
        }

        if ( dup2(src_fd, STDIN_FILENO) == -1 ) {
            error("Failed to redirect src_file %s to stdin: %s", src_file, strerror(errno));
            exit(253);
        }

        if ( src_fd != STDIN_FILENO )
            close(src_fd);

        int dst_fd = open(dst_file, O_CREAT | O_TRUNC | O_WRONLY, 0664);

        if ( dst_fd < 0 ) {
            error("Failed to open dst_file %s: %s", dst_file, strerror(errno));
            exit(252);
        }

        if ( dup2(dst_fd, STDOUT_FILENO) == -1 ) {
            error("Failed to redirect dst_file %s to stdout: %s", dst_file, strerror(errno));
            exit(251);
        }

        if ( dst_fd != STDOUT_FILENO )
            close(dst_fd);

        // Call the compression program via the shell.
        execlp("sh", "sh", "-c", options.compress_cmd.data(), (char*)0);
        error("Failed to exec(): %s", strerror(errno));
        exit(255);
    }

    int status;
    waitpid(child_pid, &status, 0);
    child_pid = -1;

    if ( ! (WIFEXITED(status) && WEXITSTATUS(status) == 0) ) {
        if ( WIFEXITED(status) )
            error("Compression of %s failed, command exit status: %d (0x%x)", src_file, WEXITSTATUS(status), status);
        else if ( WIFSIGNALED(status) )
            error("Compression of %s failed, got signal: %d (0x%x)", src_file, WTERMSIG(status), status);
        else
            error("Compression of %s failed, unknown reason/status: (0x%x)", src_file, status);

        // If the compression command failed, unlink the destination
        // file. Ignore any errors - it may not have been created.
        unlink(dst_file);
    }

    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int archive_logs() {
    int rval = 0;

    auto d = opendir(options.src_dir.data());

    if ( ! d ) {
        debug("Source directory '%s', does not exist", options.src_dir.data());
        return rval;
    }

    struct dirent* dp;
    std::vector<LogFile> log_files;

    while ( (dp = readdir(d)) ) {
        if ( dp->d_name[0] == '.' )
            continue;

        std::string path = options.src_dir + "/" + dp->d_name;

        if ( ! is_file(path.data()) ) {
            debug("Skipping archival of non-file: %s", dp->d_name);
            continue;
        }

        // Default log file format either has 4 parts delimited by "__",
        // as follows:
        //
        //     test__2020-07-16-09-43-10__2020-07-16-09-43-10__.log
        //
        // Or, 5 parts delimited by "__" where the part before the extension
        // is a generic comma separated key=value construct:
        //
        //     test__2020-07-16-09-43-10__2020-07-16-09-43-10__log_suffix=logger-1,pid=4711__.log
        //
        // The comma character is reasonable to work with on a shell and assumed
        // to not be of importance for metadata values. If this seems over-engineered,
        // maybe, but adding a plain positional parameter with an implied meaning also
        // adds a required parameter for any future extensions and we currently don't
        // have a side-channel to propagate additional information.
        //
        auto parts = split_string(dp->d_name, options.delimiter);

        if ( parts.size() != 4 && parts.size() != 5 ) {
            debug("Skipping archival of non-log: %s", dp->d_name);
            continue;
        }

        LogFile lf;
        lf.path = path;
        lf.name = parts[0];

        auto res = strptime(parts[1].data(), options.timestamp_fmt.data(), &lf.open);

        if ( ! res ) {
            debug("Skipping archival of log with bad timestamp format: %s", dp->d_name);
            continue;
        }

        if ( res != parts[1].data() + parts[1].size() )
            debug("Possible log with timestamp format mismatch: %s", dp->d_name);

        res = strptime(parts[2].data(), options.timestamp_fmt.data(), &lf.close);

        if ( ! res ) {
            debug("Skipping archival of log with bad timestamp format: %s", dp->d_name);
            continue;
        }

        if ( res != parts[2].data() + parts[2].size() )
            debug("Possible log with timestamp format mismatch: %s", dp->d_name);

        if ( parts.size() == 4 )
            lf.ext = parts[3];
        else {
            lf.ext = parts[4];

            bool metadata_error = false;

            // split_string() returns a single entry for
            // an empty string, avoid that scenario.
            std::vector<std::string> metadata_parts;
            if ( ! parts[3].empty() )
                metadata_parts = split_string(parts[3], ",");

            for ( const auto& entry : metadata_parts ) {
                auto key_value = split_string(entry, "=");
                if ( key_value.size() != 2 ) {
                    metadata_error = true;
                    break;
                }

                auto key = strip_string(key_value[0]);
                auto value = strip_string(key_value[1]);
                if ( key.empty() || value.empty() ) {
                    metadata_error = true;
                    break;
                }

                // Only log_suffix is understood as metadata.
                if ( key == "log_suffix" ) {
                    debug("Using log_suffix '%s'", value.data());
                    lf.suffix = value;
                }
                else
                    debug("Ignoring unknown metadata entry %s in %s", key.data(), dp->d_name);
            }

            if ( metadata_error ) {
                debug("Skipping archival of log with bad metadata format: %s", dp->d_name);
                continue;
            }
        }

        log_files.emplace_back(std::move(lf));
    }

    closedir(d);

    for ( const auto& lf : log_files ) {
        auto dst_dir = options.dst_dir + "/" + lf.DestDir();
        auto dst_file = dst_dir + "/" + lf.DestFile();
        auto tmp_file = dst_dir + "/.tmp." + lf.DestFile();
        const auto& src_file = lf.path;

        if ( ! make_dirs(dst_dir) ) {
            error("Skipped archiving %s: failed to create dir %s", src_file.data(), dst_dir.data());
            continue;
        }

        bool compress = ! options.compress_cmd.empty() && ! already_zipped(lf.ext);

        if ( compress ) {
            if ( ! options.compress_ext.empty() )
                dst_file += "." + options.compress_ext;

            debug("Archive via compression: %s -> %s", src_file.data(), dst_file.data());
            auto res = run_compress_cmd(src_file.data(), tmp_file.data());

            if ( res != 0 )
                continue;

            res = rename(tmp_file.data(), dst_file.data());

            if ( res == -1 ) {
                error("Failed to rename %s -> %s: %s", tmp_file.data(), dst_file.data(), strerror(errno));
                continue;
            }

            ++rval;
            res = unlink(src_file.data());

            if ( res == -1 )
                error("Failed to unlink %s; %s", src_file.data(), strerror(errno));

            continue;
        }

        auto same_fs = same_filesystem(src_file.data(), dst_dir.data());

        if ( ! same_fs ) {
            error("Failed to compare filesystems of %s and %s", src_file.data(), dst_dir.data());
            continue;
        }

        if ( *same_fs ) {
            debug("Archive via rename: %s -> %s", src_file.data(), dst_file.data());
            auto res = rename(src_file.data(), dst_file.data());

            if ( res == -1 )
                error("Failed to rename %s -> %s: %s", src_file.data(), dst_file.data(), strerror(errno));
            else
                ++rval;
        }
        else {
            debug("Archive via copy: %s -> %s", src_file.data(), dst_file.data());

            std::ifstream src;
            std::ofstream dst;
            src.exceptions(std::ifstream::failbit | std::ifstream::badbit);
            dst.exceptions(std::ofstream::failbit | std::ofstream::badbit);

            try {
                src.open(src_file, std::ios::binary);
                dst.open(tmp_file, std::ios::binary);
                dst << src.rdbuf();
            } catch ( const std::system_error& e ) {
                error("Failed to copy %s to temporary file %s: %s", src_file.data(), tmp_file.data(),
                      e.code().message().data());
                continue;
            }

            auto res = rename(tmp_file.data(), dst_file.data());

            if ( res == -1 ) {
                error("Failed to rename %s -> %s: %s", tmp_file.data(), dst_file.data(), strerror(errno));
                continue;
            }

            ++rval;
            res = unlink(src_file.data());

            if ( res == -1 )
                error("Failed to unlink %s; %s", src_file.data(), strerror(errno));
        }
    }

    return rval;
}

int main(int argc, char** argv) {
    signal(SIGTERM, signal_handler);
    parse_options(argc, argv);

    debug("Using src_dir: '%s'", options.src_dir.data());
    debug("Using dst_dir: '%s'", options.dst_dir.data());
    debug("Using oneshot option: '%d'", options.oneshot);
    debug("Using delimiter option: '%s'", options.delimiter.data());
    debug("Using timestamp format option: '%s'", options.timestamp_fmt.data());
    debug("Using compression extension option: '%s'", options.compress_ext.data());
    debug("Using compression command option: '%s'", options.compress_cmd.data());
    debug("Using poll interval: '%d'", options.idle_poll_interval);

    for ( const auto& e : options.zip_file_extensions )
        debug("Using zip-extension option: '%s'", e.data());

    if ( ! make_dirs(options.dst_dir) )
        fatal("Failed to create destination archive dir: %s", options.dst_dir.data());

    for ( ;; ) {
        using hrc = std::chrono::high_resolution_clock;
        auto t0 = hrc::now();
        auto num_archived = archive_logs();
        auto t1 = hrc::now();

        if ( num_archived > 0 ) {
            auto dt = std::chrono::duration<double>(t1 - t0).count();
            info("Archived %d logs in %f seconds", num_archived, dt);
        }

        if ( options.oneshot )
            break;

        sleep(num_archived > 0 ? 1 : options.idle_poll_interval);
    }

    return 0;
}
