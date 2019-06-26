// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

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

#include "File.h"
#include "Type.h"
#include "Expr.h"
#include "NetVar.h"
#include "Net.h"
#include "Event.h"
#include "Reporter.h"

// The following could in principle be part of a "file manager" object.

#define MAX_FILE_CACHE_SIZE 512
static int num_files_in_cache = 0;
static BroFile* head = 0;
static BroFile* tail = 0;

// Maximizes the number of open file descriptors and returns the number
// that we should use for the cache.
static int maximize_num_fds()
	{
	struct rlimit rl;
	if ( getrlimit(RLIMIT_NOFILE, &rl) < 0 )
		reporter->FatalError("maximize_num_fds(): getrlimit failed");

	if ( rl.rlim_max == RLIM_INFINITY )
		{
		// Don't try raising the current limit.
		if ( rl.rlim_cur == RLIM_INFINITY )
			// Let's not be too ambitious.
			return MAX_FILE_CACHE_SIZE;
		else
			return rl.rlim_cur / 2;
		}

	// See if we can raise the current to the maximum.
	rl.rlim_cur = rl.rlim_max;

	if ( setrlimit(RLIMIT_NOFILE, &rl) < 0 )
		reporter->FatalError("maximize_num_fds(): setrlimit failed");

	return rl.rlim_cur / 2;
	}


BroFile::BroFile(FILE* arg_f)
	{
	Init();
	f = arg_f;
	name = access = 0;
	t = base_type(TYPE_STRING);
	is_open = (f != 0);
	}

BroFile::BroFile(FILE* arg_f, const char* arg_name, const char* arg_access)
	{
	Init();
	f = arg_f;
	name = copy_string(arg_name);
	access = copy_string(arg_access);
	t = base_type(TYPE_STRING);
	is_open = (f != 0);
	}

BroFile::BroFile(const char* arg_name, const char* arg_access, BroType* arg_t)
	{
	Init();
	f = 0;
	name = copy_string(arg_name);
	access = copy_string(arg_access);
	t = arg_t ? arg_t : base_type(TYPE_STRING);

	if ( streq(name, "/dev/stdin") )
		f = stdin;
	else if ( streq(name, "/dev/stdout") )
		f = stdout;
	else if ( streq(name, "/dev/stderr") )
		f = stderr;

	if ( f )
		is_open = 1;

	else if ( ! Open() )
		{
		reporter->Error("cannot open %s: %s", name, strerror(errno));
		is_open = 0;
		okay_to_manage = 0;
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

	return 0;
	}

bool BroFile::Open(FILE* file, const char* mode)
	{
	open_time = network_time ? network_time : current_time();

	if ( ! max_files_in_cache )
		// Haven't initialized yet.
		max_files_in_cache = maximize_num_fds();

	if ( num_files_in_cache >= max_files_in_cache )
		PurgeCache();

	f = file;

	if ( ! f )
		{
		if ( ! mode )
			f = fopen(name, access);
		else
			f = fopen(name, mode);
		}

	SetBuf(buffered);

	if ( f )
		{
		// These are the only files we manage, because we open them
		// ourselves and hence don't have any surprises regarding
		// whether we're allowed to close them.
		is_open = okay_to_manage = 1;

		InsertAtBeginning();
		}
	else
		{
		// No point managing it.
		is_open = okay_to_manage = 0;
		return false;
		}

	RaiseOpenEvent();

	return true;
	}

BroFile::~BroFile()
	{
	Close();
	Unref(t);
	Unref(attrs);

	delete [] name;
	delete [] access;

#ifdef USE_PERFTOOLS_DEBUG
	heap_checker->UnIgnoreObject(this);
#endif
	}

void BroFile::Init()
	{
	is_open = okay_to_manage = is_in_cache = 0;
	position = 0;
	next = prev = 0;
	attrs = 0;
	buffered = true;
	print_hook = true;
	raw_output = false;
	t = 0;

#ifdef USE_PERFTOOLS_DEBUG
	heap_checker->IgnoreObject(this);
#endif
	}

FILE* BroFile::File()
	{
	if ( okay_to_manage && ! is_in_cache )
		f = BringIntoCache();

	return f;
	}

FILE* BroFile::BringIntoCache()
	{
	char buf[256];

	if ( f )
		reporter->InternalError("BroFile non-nil non-open file");

	if ( num_files_in_cache >= max_files_in_cache )
		PurgeCache();

	if ( position == 0 )
		// Need to truncate it.
		f = fopen(name, access);
	else
		// Don't clobber it.
		f = fopen(name, "a");

	if ( ! f )
		{
		bro_strerror_r(errno, buf, sizeof(buf));
		reporter->Error("can't open %s: %s", name, buf);

		f = fopen("/dev/null", "w");

		if ( f )
			{
			okay_to_manage = 0;
			return f;
			}

		bro_strerror_r(errno, buf, sizeof(buf));
		reporter->Error("can't open /dev/null: %s", buf);
		return 0;
		}

	if ( fseek(f, position, SEEK_SET) < 0 )
		{
		bro_strerror_r(errno, buf, sizeof(buf));
		reporter->Error("reopen seek failed: %s", buf);
		}

	InsertAtBeginning();
	RaiseOpenEvent();

	return f;
	}

FILE* BroFile::Seek(long new_position)
	{
	if ( ! File() )
		return 0;

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

int BroFile::Close()
	{
	if ( ! is_open )
		return 1;

	// Do not close stdin/stdout/stderr.
	if ( f == stdin || f == stdout || f == stderr )
		return 0;

	if ( is_in_cache )
		{
		Unlink();
		if ( f )
			{
			fclose(f);
			f = 0;
			open_time = 0;
			}

		is_open = 0;
		okay_to_manage = 0; // no longer managed since will never reopen

		return 1;
		}

	// Not managed.
	if ( ! f )
		return 0;

	fclose(f);
	f = 0;

	return 1;
	}

void BroFile::Suspend()
	{
	if ( ! is_in_cache )
		reporter->InternalError("BroFile::Suspend() called for non-cached file");

	if ( ! is_open )
		reporter->InternalError("BroFile::Suspend() called for non-open file");

	Unlink();

	if ( ! f )
		reporter->InternalError("BroFile::Suspend() called for nil file");

	if ( (position = ftell(f)) < 0 )
		{
		char buf[256];
		bro_strerror_r(errno, buf, sizeof(buf));
		reporter->Error("ftell failed: %s", buf);
		position = 0;
		}

	fclose(f);
	f = 0;
	}

void BroFile::PurgeCache()
	{
	if ( tail )
		{
		tail->Suspend();
		return;
		}

	reporter->InternalWarning("BroFile purge of empty cache");
	}

void BroFile::Unlink()
	{
	if ( is_in_cache )
		{
		if ( head == this )
			head = Next();
		else
			Prev()->SetNext(next);

		if ( tail == this )
			tail = Prev();
		else
			Next()->SetPrev(prev);

		if ( (head || tail) && ! (head && tail) )
			reporter->InternalError("BroFile link list botch");

		is_in_cache = 0;
		prev = next = 0;

		if ( --num_files_in_cache < 0 )
			reporter->InternalError("BroFile underflow of file cache");
		}
	}

void BroFile::InsertAtBeginning()
	{
	if ( ! head )
		{
		head = tail = this;
		next = prev = 0;
		}
	else
		{
		SetNext(head);
		SetPrev(0);
		head->SetPrev(this);
		head = this;
		}

	if ( ++num_files_in_cache > max_files_in_cache )
		reporter->InternalError("BroFile overflow of file cache");

	is_in_cache = 1;
	}

void BroFile::MoveToBeginning()
	{
	if ( head == this )
		return;	// already at the beginning

	if ( ! is_in_cache || ! prev )
		reporter->InternalError("BroFile inconsistency in MoveToBeginning()");

	Unlink();
	InsertAtBeginning();
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
		return 0;

	// Do not rotate stdin/stdout/stderr.
	if ( f == stdin || f == stdout || f == stderr )
		return 0;

	if ( okay_to_manage && ! is_in_cache )
		BringIntoCache();

	RecordVal* info = new RecordVal(rotate_info);
	FILE* newf = rotate_file(name, info);

	if ( ! newf )
		{
		Unref(info);
		return 0;
		}

	info->Assign(2, new Val(open_time, TYPE_TIME));

	Unlink();
 	fclose(f);
	f = 0;

	Open(newf);
	return info;
	}

void BroFile::CloseCachedFiles()
	{
	BroFile* next;
	for ( BroFile* f = head; f; f = next )
		{
		next = f->next;
		if ( f->is_in_cache )
			f->Close();
		}
	}

int BroFile::Write(const char* data, int len)
	{
	if ( ! is_open )
		return 0;

	if ( ! is_in_cache && okay_to_manage )
		BringIntoCache();

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
	Event* event = new ::Event(::file_opened, {new Val(this)});
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
	for ( BroFile* f = head; f; f = f->next )
		{
		if ( f->name && streq(name, f->name) )
			return f;
		}

	return new BroFile(name, "w", 0);
	}

