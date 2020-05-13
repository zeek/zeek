// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "File.h"

#include <sys/types.h>
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <sys/resource.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

#include <algorithm>

#include "Attr.h"
#include "Type.h"
#include "Expr.h"
#include "NetVar.h"
#include "Net.h"
#include "Event.h"
#include "Reporter.h"
#include "Desc.h"
#include "Var.h"

std::list<std::pair<std::string, BroFile*>> BroFile::open_files;

// Maximizes the number of open file descriptors.
static void maximize_num_fds()
	{
	struct rlimit rl;
	if ( getrlimit(RLIMIT_NOFILE, &rl) < 0 )
		reporter->FatalError("maximize_num_fds(): getrlimit failed");

	if ( rl.rlim_max == RLIM_INFINITY )
		{
		// Don't try raising the current limit.
		return;
		}

	// See if we can raise the current to the maximum.
	rl.rlim_cur = rl.rlim_max;

	if ( setrlimit(RLIMIT_NOFILE, &rl) < 0 )
		reporter->FatalError("maximize_num_fds(): setrlimit failed");
	}

BroFile::BroFile(FILE* arg_f)
	{
	Init();
	f = arg_f;
	name = access = nullptr;
	t = base_type(TYPE_STRING);
	is_open = (f != nullptr);
	}

BroFile::BroFile(FILE* arg_f, const char* arg_name, const char* arg_access)
	{
	Init();
	f = arg_f;
	name = copy_string(arg_name);
	access = copy_string(arg_access);
	t = base_type(TYPE_STRING);
	is_open = (f != nullptr);
	}

BroFile::BroFile(const char* arg_name, const char* arg_access)
	{
	Init();
	f = nullptr;
	name = copy_string(arg_name);
	access = copy_string(arg_access);
	t = base_type(TYPE_STRING);

	if ( streq(name, "/dev/stdin") )
		f = stdin;
	else if ( streq(name, "/dev/stdout") )
		f = stdout;
	else if ( streq(name, "/dev/stderr") )
		f = stderr;

	if ( f )
		is_open = true;

	else if ( ! Open() )
		{
		reporter->Error("cannot open %s: %s", name, strerror(errno));
		is_open = false;
		}
	}

const char* BroFile::Name() const
	{
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

bool BroFile::Open(FILE* file, const char* mode)
	{
	static bool fds_maximized = false;
	open_time = network_time ? network_time : current_time();

	if ( ! fds_maximized )
		{
		// Haven't initialized yet.
		maximize_num_fds();
		fds_maximized = true;
		}

	f = file;

	if ( ! f )
		{
		if ( ! mode )
			f = fopen(name, access);
		else
			f = fopen(name, mode);
		}

	SetBuf(buffered);

	if ( ! f )
		{
		is_open = false;
		return false;
		}

	is_open = true;
	open_files.emplace_back(std::make_pair(name, this));

	RaiseOpenEvent();

	return true;
	}

BroFile::~BroFile()
	{
	Close();
	Unref(attrs);

	delete [] name;
	delete [] access;

#ifdef USE_PERFTOOLS_DEBUG
	heap_checker->UnIgnoreObject(this);
#endif
	}

void BroFile::Init()
	{
	open_time = 0;
	is_open = false;
	attrs = nullptr;
	buffered = true;
	raw_output = false;

#ifdef USE_PERFTOOLS_DEBUG
	heap_checker->IgnoreObject(this);
#endif
	}

FILE* BroFile::File()
	{
	return f;
	}

FILE* BroFile::Seek(long new_position)
	{
	if ( ! File() )
		return nullptr;

	if ( fseek(f, new_position, SEEK_SET) < 0 )
		reporter->Error("seek failed");

	return f;
	}

void BroFile::SetBuf(bool arg_buffered)
	{
	if ( ! f )
		return;

	if ( setvbuf(f, NULL, arg_buffered ? _IOFBF : _IOLBF, 0) != 0 )
		reporter->Error("setvbuf failed");

	buffered = arg_buffered;
	}

bool BroFile::Close()
	{
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

void BroFile::Unlink()
	{
	for ( auto it = open_files.begin(); it != open_files.end(); ++it)
		{
		if ( (*it).second == this )
			{
			open_files.erase(it);
			return;
			}
		}
	}

void BroFile::Describe(ODesc* d) const
	{
	d->AddSP("file");

	if ( name )
		{
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

void BroFile::SetAttrs(Attributes* arg_attrs)
	{
	if ( ! arg_attrs )
		return;

	attrs = arg_attrs;
	Ref(attrs);

	if ( attrs->FindAttr(ATTR_RAW_OUTPUT) )
		EnableRawOutput();
	}

RecordVal* BroFile::Rotate()
	{
	if ( ! is_open )
		return nullptr;

	// Do not rotate stdin/stdout/stderr.
	if ( f == stdin || f == stdout || f == stderr )
		return nullptr;

	static auto rotate_info = zeek::id::lookup_type<RecordType>("rotate_info");
	RecordVal* info = new RecordVal(rotate_info);
	FILE* newf = rotate_file(name, info);

	if ( ! newf )
		{
		Unref(info);
		return nullptr;
		}

	info->Assign(2, make_intrusive<Val>(open_time, TYPE_TIME));

	Unlink();

 	fclose(f);
	f = nullptr;

	Open(newf);
	return info;
	}

void BroFile::CloseOpenFiles()
	{
	auto it = open_files.begin();
	while ( it != open_files.end() )
		{
		auto el = it++;
		(*el).second->Close();
		}
	}

bool BroFile::Write(const char* data, int len)
	{
	if ( ! is_open )
		return false;

	if ( ! len )
		len = strlen(data);

	if ( fwrite(data, len, 1, f) < 1 )
		return false;

	return true;
	}

void BroFile::RaiseOpenEvent()
	{
	if ( ! ::file_opened )
		return;

	Ref(this);
	Event* event = new ::Event(::file_opened, {make_intrusive<Val>(this)});
	mgr.Dispatch(event, true);
	}

double BroFile::Size()
	{
	fflush(f);
	struct stat s;
	if ( fstat(fileno(f), &s) < 0 )
		{
		reporter->Error("can't stat fd for %s: %s", name, strerror(errno));
		return 0;
		}

	return s.st_size;
	}

BroFile* BroFile::GetFile(const char* name)
	{
	for ( const auto &el : open_files )
		{
		if ( el.first == name )
			{
			Ref(el.second);
			return el.second;
			}
		}

	return new BroFile(name, "w");
	}
