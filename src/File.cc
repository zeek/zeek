// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/File.h"

#include "zeek/zeek-config.h"

#include <sys/types.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <ctime>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <ctime>
#endif
#endif
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>

#include "zeek/Attr.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/Expr.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/Type.h"
#include "zeek/Var.h"

namespace zeek {

std::list<std::pair<std::string, File*>> File::open_files;

// Maximizes the number of open file descriptors.
static void maximize_num_fds() {
    struct rlimit rl;
    if ( getrlimit(RLIMIT_NOFILE, &rl) < 0 )
        reporter->FatalError("maximize_num_fds(): getrlimit failed");

    if ( rl.rlim_max == RLIM_INFINITY ) {
        // Don't try raising the current limit.
        return;
    }

    // See if we can raise the current to the maximum.
    rl.rlim_cur = rl.rlim_max;

    if ( setrlimit(RLIMIT_NOFILE, &rl) < 0 )
        reporter->FatalError("maximize_num_fds(): setrlimit failed");
}

File::File(FILE* arg_f) {
    Init();
    f = arg_f;
    name = access = nullptr;
    t = base_type(TYPE_STRING);
    is_open = (f != nullptr);
}

File::File(FILE* arg_f, const char* arg_name, const char* arg_access) {
    Init();
    f = arg_f;
    name = util::copy_string(arg_name);
    access = util::copy_string(arg_access);
    t = base_type(TYPE_STRING);
    is_open = (f != nullptr);
}

File::File(const char* arg_name, const char* arg_access) {
    Init();
    f = nullptr;
    name = util::copy_string(arg_name);
    access = util::copy_string(arg_access);
    t = base_type(TYPE_STRING);

    if ( util::streq(name, "/dev/stdin") )
        f = stdin;
    else if ( util::streq(name, "/dev/stdout") )
        f = stdout;
    else if ( util::streq(name, "/dev/stderr") )
        f = stderr;

    if ( f )
        is_open = true;

    else if ( ! Open() ) {
        reporter->Error("cannot open %s: %s", name, strerror(errno));
        is_open = false;
    }
}

const char* File::Name() const {
    if ( name )
        return name;

    if ( f == stdin )
        return "/dev/stdin";

    if ( f == stdout )
        return "/dev/stdout";

    if ( f == stderr )
        return "/dev/stderr";

    return nullptr;
}

bool File::Open(FILE* file, const char* mode) {
    static bool fds_maximized = false;
    open_time = run_state::network_time ? run_state::network_time : util::current_time();

    if ( ! fds_maximized ) {
        // Haven't initialized yet.
        maximize_num_fds();
        fds_maximized = true;
    }

    f = file;

    if ( ! f ) {
        if ( ! mode )
            f = fopen(name, access);
        else
            f = fopen(name, mode);
    }

    SetBuf(buffered);

    if ( ! f ) {
        is_open = false;
        return false;
    }

    is_open = true;
    open_files.emplace_back(name, this);

    RaiseOpenEvent();

    return true;
}

File::~File() {
    Close();
    Unref(attrs);

    delete[] name;
    delete[] access;

#ifdef USE_PERFTOOLS_DEBUG
    heap_checker->UnIgnoreObject(this);
#endif
}

void File::Init() {
    open_time = 0;
    is_open = false;
    attrs = nullptr;
    buffered = true;
    raw_output = false;

#ifdef USE_PERFTOOLS_DEBUG
    heap_checker->IgnoreObject(this);
#endif
}

FILE* File::FileHandle() { return f; }

FILE* File::Seek(long new_position) {
    if ( ! FileHandle() )
        return nullptr;

    if ( fseek(f, new_position, SEEK_SET) < 0 )
        reporter->Error("seek failed");

    return f;
}

void File::SetBuf(bool arg_buffered) {
    if ( ! f )
        return;

    if ( util::detail::setvbuf(f, NULL, arg_buffered ? _IOFBF : _IOLBF, 0) != 0 )
        reporter->Error("setvbuf failed");

    buffered = arg_buffered;
}

bool File::Close() {
    if ( ! is_open )
        return true;

    // Do not close stdin/stdout/stderr.
    if ( f == stdin || f == stdout || f == stderr )
        return false;

    if ( ! f )
        return false;

    fclose(f);
    f = nullptr;
    open_time = 0;
    is_open = false;

    Unlink();

    return true;
}

void File::Unlink() {
    for ( auto it = open_files.begin(); it != open_files.end(); ++it ) {
        if ( (*it).second == this ) {
            open_files.erase(it);
            return;
        }
    }
}

void File::Describe(ODesc* d) const {
    d->AddSP("file");

    if ( name ) {
        d->Add("\"");
        d->Add(name);
        d->AddSP("\"");
    }

    d->AddSP("of");
    if ( t )
        t->Describe(d);
    else
        d->Add("(no type)");
}

void File::SetAttrs(detail::Attributes* arg_attrs) {
    if ( ! arg_attrs )
        return;

    attrs = arg_attrs;
    Ref(attrs);

    if ( attrs->Find(detail::ATTR_RAW_OUTPUT) )
        EnableRawOutput();
}

RecordVal* File::Rotate() {
    if ( ! is_open )
        return nullptr;

    // Do not rotate stdin/stdout/stderr.
    if ( f == stdin || f == stdout || f == stderr )
        return nullptr;

    static auto rotate_info = id::find_type<RecordType>("rotate_info");
    auto* info = new RecordVal(rotate_info);
    FILE* newf = util::detail::rotate_file(name, info);

    if ( ! newf ) {
        Unref(info);
        return nullptr;
    }

    info->AssignTime(2, open_time);

    Unlink();

    fclose(f);
    f = nullptr;

    Open(newf);
    return info;
}

void File::CloseOpenFiles() {
    auto it = open_files.begin();
    while ( it != open_files.end() ) {
        auto el = it++;
        (*el).second->Close();
    }
}

bool File::Write(const char* data, int len) {
    if ( ! is_open )
        return false;

    if ( ! len )
        len = strlen(data);

    if ( fwrite(data, len, 1, f) < 1 )
        return false;

    return true;
}

void File::RaiseOpenEvent() {
    if ( ! ::file_opened )
        return;

    FilePtr bf{NewRef{}, this};
    event_mgr.Dispatch(::file_opened, {make_intrusive<FileVal>(std::move(bf))});
}

double File::Size() {
    fflush(f);
    struct stat s;
    if ( fstat(fileno(f), &s) < 0 ) {
        reporter->Error("can't stat fd for %s: %s", name, strerror(errno));
        return 0;
    }

    return s.st_size;
}

FilePtr File::Get(const char* name) {
    for ( const auto& el : open_files )
        if ( el.first == name )
            return {NewRef{}, el.second};

    return make_intrusive<File>(name, "w");
}

} // namespace zeek
