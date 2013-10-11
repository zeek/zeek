// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

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
#include "Timer.h"
#include "Expr.h"
#include "NetVar.h"
#include "Net.h"
#include "Serializer.h"
#include "Event.h"
#include "Reporter.h"

// Timer which on dispatching rotates the file.
class RotateTimer : public Timer {
public:
	RotateTimer(double t, BroFile* f, bool arg_raise) : Timer(t, TIMER_ROTATE)
		{ file = f; raise = arg_raise; name = copy_string(f->Name()); }
	~RotateTimer();

	void Dispatch(double t, int is_expire);

protected:
	BroFile* file;
	bool raise;
	const char* name;
};

RotateTimer::~RotateTimer()
	{
	if ( file->rotate_timer == this )
		file->rotate_timer = 0;

	delete [] name;
	}

void RotateTimer::Dispatch(double t, int is_expire)
	{
	file->rotate_timer = 0;

	if ( ! is_expire )
		{
		if ( raise )
			{
			val_list* vl = new val_list;
			Ref(file);
			vl->append(new Val(file));
			mgr.QueueEvent(rotate_interval, vl);
			}

		file->InstallRotateTimer();
		}
	}


// The following could in principle be part of a "file manager" object.

#define MAX_FILE_CACHE_SIZE 512
static int num_files_in_cache = 0;
static BroFile* head = 0;
static BroFile* tail = 0;

double BroFile::default_rotation_interval = 0;
double BroFile::default_rotation_size = 0;

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

	if ( f )
		UpdateFileSize();
	}

BroFile::BroFile(FILE* arg_f, const char* arg_name, const char* arg_access)
	{
	Init();
	f = arg_f;
	name = copy_string(arg_name);
	access = copy_string(arg_access);
	t = base_type(TYPE_STRING);
	is_open = (f != 0);

	if ( f )
		UpdateFileSize();
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
		return"/dev/stdin";

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

	if ( default_rotation_interval &&
	     (! attrs || ! attrs->FindAttr(ATTR_ROTATE_INTERVAL)) )
		rotate_interval = default_rotation_interval;

	if ( default_rotation_size &&
	     (! attrs || ! attrs->FindAttr(ATTR_ROTATE_SIZE)) )
		rotate_size = default_rotation_size;

	InstallRotateTimer();

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
		UpdateFileSize();
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
	delete [] cipher_buffer;

#ifdef USE_PERFTOOLS_DEBUG
	heap_checker->UnIgnoreObject(this);
#endif
	}

void BroFile::Init()
	{
	is_open = okay_to_manage = is_in_cache = 0;
	position = 0;
	next = prev = 0;
	rotate_timer = 0;
	rotate_interval = 0.0;
	rotate_size = current_size = 0.0;
	open_time = 0;
	attrs = 0;
	buffered = true;
	print_hook = true;
	raw_output = false;
	t = 0;
	pub_key = 0;
	cipher_ctx = 0;
	cipher_buffer = 0;

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
		strerror_r(errno, buf, sizeof(buf));
		reporter->Error("can't open %s: %s", name, buf);

		f = fopen("/dev/null", "w");

		if ( f )
			{
			okay_to_manage = 0;
			return f;
			}

		strerror_r(errno, buf, sizeof(buf));
		reporter->Error("can't open /dev/null: %s", buf);
		return 0;
		}

	RaiseOpenEvent();
	UpdateFileSize();

	if ( fseek(f, position, SEEK_SET) < 0 )
		{
		strerror_r(errno, buf, sizeof(buf));
		reporter->Error("reopen seek failed: %s", buf);
		}

	InsertAtBeginning();

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
	if ( rotate_timer )
		{
		timer_mgr->Cancel(rotate_timer);
		rotate_timer = 0;
		}

	if ( ! is_open )
		return 1;

	FinishEncrypt();

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
		strerror_r(errno, buf, sizeof(buf));
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

	Attr* ef = attrs->FindAttr(ATTR_ROTATE_INTERVAL);
	if ( ef )
		rotate_interval = ef->AttrExpr()->ExprVal()->AsInterval();

	ef = attrs->FindAttr(ATTR_ROTATE_SIZE);
	if ( ef )
		rotate_size = ef->AttrExpr()->ExprVal()->AsDouble();

	ef = attrs->FindAttr(ATTR_ENCRYPT);
	if ( ef )
		{
		if ( ef->AttrExpr() )
			InitEncrypt(ef->AttrExpr()->ExprVal()->AsString()->CheckString());
		else
			InitEncrypt(log_encryption_key->AsString()->CheckString());
		}

	if ( attrs->FindAttr(ATTR_RAW_OUTPUT) )
		EnableRawOutput();

	InstallRotateTimer();
	}

void BroFile::SetRotateInterval(double secs)
	{
	rotate_interval = secs;
	InstallRotateTimer();
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

void BroFile::InstallRotateTimer()
	{
	if ( terminating )
		return;

	if ( rotate_timer )
		{
		timer_mgr->Cancel(rotate_timer);
		rotate_timer = 0;
		}

	if ( rotate_interval )
		{
		// When this is called for the first time, network_time can
		// still be zero. If so, we set a timer which fires
		// immediately but doesn't rotate when it expires.

		if ( ! network_time )
			rotate_timer = new RotateTimer(1, this, false);
		else
			{
			if ( ! open_time )
				open_time = network_time;

			const char* base_time = log_rotate_base_time ?
				log_rotate_base_time->AsString()->CheckString() : 0;

			double base = parse_rotate_base_time(base_time);
			double delta_t =
				calc_next_rotate(network_time, rotate_interval, base);
			rotate_timer = new RotateTimer(network_time + delta_t,
							this, true);
			}

		timer_mgr->Add(rotate_timer);
		}
	}

void BroFile::SetDefaultRotation(double interval, double max_size)
	{
	for ( BroFile* f = head; f; f = f->next )
		{
		if ( ! (f->attrs && f->attrs->FindAttr(ATTR_ROTATE_INTERVAL)) )
			{
			f->rotate_interval = interval;
			f->InstallRotateTimer();
			}

		if ( ! (f->attrs && f->attrs->FindAttr(ATTR_ROTATE_SIZE)) )
			f->rotate_size = max_size;
		}

	default_rotation_interval = interval;
	default_rotation_size = max_size;
	}

void BroFile::CloseCachedFiles()
	{
	BroFile* next;
	for ( BroFile* f = head; f; f = next )
		{
		// Send final rotate events (immediately).
		if ( f->rotate_interval )
			{
			val_list* vl = new val_list;
			Ref(f);
			vl->append(new Val(f));
			Event* event = new Event(::rotate_interval, vl);
			mgr.Dispatch(event, true);
			}

		if ( f->rotate_size )
			{
			val_list* vl = new val_list;
			Ref(f);
			vl->append(new Val(f));
			Event* event = new ::Event(::rotate_size, vl);
			mgr.Dispatch(event, true);
			}

		next = f->next;
		if ( f->is_in_cache )
			f->Close();
		}
	}

void BroFile::InitEncrypt(const char* keyfile)
	{
	if ( ! (pub_key || keyfile) )
		return;

	if ( ! pub_key )
		{
		FILE* key = fopen(keyfile, "r");

		if ( ! key )
			{
			reporter->Error("can't open key file %s: %s", keyfile, strerror(errno));
			Close();
			return;
			}

		pub_key = PEM_read_PUBKEY(key, 0, 0, 0);
		if ( ! pub_key )
			{
			reporter->Error("can't read key from %s: %s", keyfile,
					ERR_error_string(ERR_get_error(), 0));
			Close();
			return;
			}
		}

	// Depending on the OpenSSL version, EVP_*_cbc()
	// returns a const or a non-const.
	EVP_CIPHER* cipher_type = (EVP_CIPHER*) EVP_bf_cbc();
	cipher_ctx = new EVP_CIPHER_CTX;

	unsigned char secret[EVP_PKEY_size(pub_key)];
	unsigned char* psecret = secret;
	unsigned int secret_len;

	int iv_len = EVP_CIPHER_iv_length(cipher_type);
	unsigned char iv[iv_len];

	if ( ! EVP_SealInit(cipher_ctx, cipher_type, &psecret,
				(int*) &secret_len, iv, &pub_key, 1) )
		{
		reporter->Error("can't init cipher context for %s: %s", keyfile,
				ERR_error_string(ERR_get_error(), 0));
		Close();
		return;
		}

	secret_len = htonl(secret_len);

	if ( ! (fwrite("BROENC1", 7, 1, f) &&
		fwrite(&secret_len, sizeof(secret_len), 1, f) &&
		fwrite(secret, ntohl(secret_len), 1, f) &&
		fwrite(iv, iv_len, 1, f)) )
		{
		reporter->Error("can't write header to log file %s: %s",
				name, strerror(errno));
		Close();
		return;
		}

	int buf_size = MIN_BUFFER_SIZE + EVP_CIPHER_block_size(cipher_type);
	cipher_buffer = new unsigned char[buf_size];
	}

void BroFile::FinishEncrypt()
	{
	if ( ! is_open )
		return;

	if ( ! pub_key )
		return;

	if ( cipher_ctx )
		{
		int outl;
		EVP_SealFinal(cipher_ctx, cipher_buffer, &outl);

		if ( outl && ! fwrite(cipher_buffer, outl, 1, f) )
			{
			reporter->Error("write error for %s: %s",
					name, strerror(errno));
			return;
			}

		delete cipher_ctx;
		cipher_ctx = 0;
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

	if ( cipher_ctx )
		{
		while ( len )
			{
			int outl;
			int inl = min(+MIN_BUFFER_SIZE, len);

			if ( ! EVP_SealUpdate(cipher_ctx, cipher_buffer, &outl,
						(unsigned char*)data, inl) )
				{
				reporter->Error("encryption error for %s: %s",
					name,
					ERR_error_string(ERR_get_error(), 0));
				Close();
				return 0;
				}

			if ( outl && ! fwrite(cipher_buffer, outl, 1, f) )
				{
				reporter->Error("write error for %s: %s",
						name, strerror(errno));
				Close();
				return 0;
				}

			data += inl;
			len -= inl;
			}

		return 1;
		}

	len = fwrite(data, 1, len, f);
	if ( len <= 0 )
		return false;

	if ( rotate_size && current_size < rotate_size && current_size + len >= rotate_size )
		{
		val_list* vl = new val_list;
		vl->append(new Val(this));
		mgr.QueueEvent(::rotate_size, vl);
		}

	// This does not work if we seek around. But none of the logs does that
	// and we avoid stat()'ing the file all the time.
	current_size += len;

	return true;
	}

void BroFile::RaiseOpenEvent()
	{
	if ( ! ::file_opened )
		return;

	val_list* vl = new val_list;
	Ref(this);
	vl->append(new Val(this));
	Event* event = new ::Event(::file_opened, vl);
	mgr.Dispatch(event, true);
	}

void BroFile::UpdateFileSize()
	{
	struct stat s;
	if ( fstat(fileno(f), &s) < 0 )
		{
		reporter->Error("can't stat fd for %s: %s", name, strerror(errno));
		current_size = 0;
		return;
		}

	current_size = double(s.st_size);
	}

bool BroFile::Serialize(SerialInfo* info) const
	{
	return SerialObj::Serialize(info);
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

BroFile* BroFile::Unserialize(UnserialInfo* info)
	{
	BroFile* file = (BroFile*) SerialObj::Unserialize(info, SER_BRO_FILE);

	if ( ! file )
		return 0;

	if ( file->is_open )
		return file;

	// If there is already an object for this file, return it.
	if ( file->name )
		{
		for ( BroFile* f = head; f; f = f->next )
			{
			if ( f->name && streq(file->name, f->name) )
				{
				Unref(file);
				Ref(f);
				return f;
				}
			}
		}

	// Otherwise, open, but don't clobber.
	if ( ! file->Open(0, "a") )
		{
		info->s->Error(fmt("cannot open %s: %s",
					file->name, strerror(errno)));
		return 0;
		}

	// Here comes a hack.  This method will return a pointer to a newly
	// instantiated file object.  As soon as this pointer is Unref'ed, the
	// file will be closed.  That means that when we unserialize the same
	// file next time, we will re-open it and thereby delete the first one,
	// i.e., we will be keeping to delete what we've written just before.
	//
	// To avoid this loop, we do an extra Ref here, i.e., this file will
	// *never* be closed anymore (as long the file cache does not overflow).
	Ref(file);

	// We deliberately override log rotation attributes with our defaults.
	file->rotate_interval = log_rotate_interval;
	file->rotate_size = log_max_size;
	file->InstallRotateTimer();
	file->SetBuf(file->buffered);

	return file;
	}

IMPLEMENT_SERIAL(BroFile, SER_BRO_FILE);

bool BroFile::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BRO_FILE, BroObj);

	const char* s = name;

	if ( ! okay_to_manage )
		{
		// We can handle stdin/stdout/stderr but no others.
		if ( f == stdin )
			s = "/dev/stdin";
		else if ( f == stdout )
			s = "/dev/stdout";
		else if ( f == stderr )
			s = "/dev/stderr";
		else
			{
			// We don't manage the file, and therefore don't
			// really know how to pass it on to the other side.
			// However, in order to not abort communication
			// when this happens, we still send the name if we
			// have one; or if we don't, we create a special
			// "dont-have-a-file" file to be created on the
			// receiver side.
			if ( ! s )
				s = "unmanaged-bro-output-file.log";
			}
		}

	if ( ! (SERIALIZE(s) && SERIALIZE(buffered)) )
		return false;

	SERIALIZE_OPTIONAL_STR(access);

	if ( ! t->Serialize(info) )
		return false;

	SERIALIZE_OPTIONAL(attrs);
	return true;
	}

bool BroFile::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroObj);

	if ( ! (UNSERIALIZE_STR(&name, 0) && UNSERIALIZE(&buffered)) )
		return false;

	UNSERIALIZE_OPTIONAL_STR(access);

	t = BroType::Unserialize(info);
	if ( ! t )
		return false;

	UNSERIALIZE_OPTIONAL(attrs, Attributes::Unserialize(info));

	// Parse attributes.
	SetAttrs(attrs);
	// SetAttrs() has ref'ed attrs again.
	Unref(attrs);

	// Bind stdin/stdout/stderr.
	FILE* file = 0;
	is_open = false;
	f = 0;

	if ( streq(name, "/dev/stdin") )
		file = stdin;
	else if ( streq(name, "/dev/stdout") )
		file = stdout;
	else if ( streq(name, "/dev/stderr") )
		file = stderr;

	if ( file )
		{
		delete [] name;
		name = 0;
		f = file;
		is_open = true;
		}

	return true;
	}
