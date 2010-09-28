// $Id: util.cc 6916 2009-09-24 20:48:36Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>

#ifdef HAVE_MALLINFO
# include <malloc.h>
#endif

#include "input.h"
#include "util.h"
#include "Obj.h"
#include "md5.h"
#include "Val.h"
#include "NetVar.h"
#include "Net.h"

char* copy_string(const char* s)
	{
	char* c = new char[strlen(s)+1];
	strcpy(c, s);
	return c;
	}

int streq(const char* s1, const char* s2)
	{
	return ! strcmp(s1, s2);
	}

int expand_escape(const char*& s)
	{
	switch ( *(s++) ) {
	case 'b': return '\b';
	case 'f': return '\f';
	case 'n': return '\n';
	case 'r': return '\r';
	case 't': return '\t';
	case 'a': return '\a';
	case 'v': return '\v';

	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7':
		{ // \<octal>{1,3}
		--s;	// put back the first octal digit
		const char* start = s;

		// Don't increment inside loop control
		// because if isdigit() is a macro it might
		// expand into multiple increments ...

		// Here we define a maximum length for escape sequence
		// to allow easy handling of string like: "^H0" as
		// "\0100".

		for ( int len = 0; len < 3 && isascii(*s) && isdigit(*s);
		      ++s, ++len)
			;

		int result;
		if ( sscanf(start, "%3o", &result) != 1 )
			{
			warn("bad octal escape: ", start);
			result = 0;
			}

		return result;
		}

	case 'x':
		{ /* \x<hex> */
		const char* start = s;

		// Look at most 2 characters, so that "\x0ddir" -> "^Mdir".
		for ( int len = 0; len < 2 && isascii(*s) && isxdigit(*s);
		      ++s, ++len)
			;

		int result;
		if ( sscanf(start, "%2x", &result) != 1 )
			{
			warn("bad hexadecimal escape: ", start);
			result = 0;
			}

		return result;
		}

	default:
		return s[-1];
	}
	}

char* skip_whitespace(char* s)
	{
	while ( *s == ' ' || *s == '\t' )
		++s;
	return s;
	}

const char* skip_whitespace(const char* s)
	{
	while ( *s == ' ' || *s == '\t' )
		++s;
	return s;
	}

char* skip_whitespace(char* s, char* end_of_s)
	{
	while ( s < end_of_s && (*s == ' ' || *s == '\t') )
		++s;
	return s;
	}

const char* skip_whitespace(const char* s, const char* end_of_s)
	{
	while ( s < end_of_s && (*s == ' ' || *s == '\t') )
		++s;
	return s;
	}

char* skip_digits(char* s)
	{
	while ( *s && isdigit(*s) )
		++s;
	return s;
	}

char* get_word(char*& s)
	{
	char* w = s;
	while ( *s && ! isspace(*s) )
		++s;

	if ( *s )
		{
		*s = '\0';	// terminate the word
		s = skip_whitespace(s+1);
		}

	return w;
	}

void get_word(int length, const char* s, int& pwlen, const char*& pw)
	{
	pw = s;

	int len = 0;
	while ( len < length && *s && ! isspace(*s) )
		{
		++s;
		++len;
		}

	pwlen = len;
	}

void to_upper(char* s)
	{
	while ( *s )
		{
		if ( islower(*s) )
			*s = toupper(*s);
		++s;
		}
	}

const char* strchr_n(const char* s, const char* end_of_s, char ch)
	{
	for ( ; s < end_of_s; ++s )
		if ( *s == ch )
			return s;

	return 0;
	}

const char* strrchr_n(const char* s, const char* end_of_s, char ch)
	{
	for ( --end_of_s; end_of_s >= s; --end_of_s )
		if ( *end_of_s == ch )
			return end_of_s;

	return 0;
	}

int decode_hex(char ch)
	{
	if ( ch >= '0' && ch <= '9' )
		return ch - '0';

	if ( ch >= 'A' && ch <= 'F' )
		return ch - 'A' + 10;

	if ( ch >= 'a' && ch <= 'f' )
		return ch - 'a' + 10;

	return -1;
	}

unsigned char encode_hex(int h)
	{
	static const char hex[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8',
		'9', 'A', 'B', 'C', 'D', 'E', 'F'
	};

	if  ( h < 0 || h >= 16 )
		{
		internal_error("illegal value for encode_hex: %d", h);
		return 'X';
		}

	return hex[h];
	}

// Same as strpbrk except that s is not NUL-terminated, but limited by
// len. Note that '\0' is always implicitly contained in charset.
const char* strpbrk_n(size_t len, const char* s, const char* charset)
	{
	for ( const char* p = s; p < s + len; ++p )
		if ( strchr(charset, *p) )
			return p;

	return 0;
	}

int strcasecmp_n(int b_len, const char* b, const char* t)
	{
	if ( ! b )
		return -1;

	int i;
	for ( i = 0; i < b_len; ++i )
		{
		char c1 = islower(b[i]) ? toupper(b[i]) : b[i];
		char c2 = islower(t[i]) ? toupper(t[i]) : t[i];

		if ( c1 < c2 )
			return -1;

		if ( c1 > c2 )
			return 1;
		}

	return t[i] != '\0';
	}

#ifndef HAVE_STRCASESTR
// This code is derived from software contributed to BSD by Chris Torek.
char* strcasestr(const char* s, const char* find)
	{
	char c = *find++;
	if ( c )
		{
		c = tolower((unsigned char) c);

		size_t len = strlen(find);

		do {
			char sc;
			do {
				sc = *s++;
				if ( sc == 0 )
					return 0;
			} while ( char(tolower((unsigned char) sc)) != c );
		} while ( strcasecmp_n(len, s, find) != 0 );

		--s;
		}

	return (char*) s;
	}
#endif

int atoi_n(int len, const char* s, const char** end, int base, int& result)
	{
	int n = 0;
	int neg = 0;

	if ( len > 0 && *s == '-' )
		{
		neg = 1;
		--len; ++s;
		}

	int i;
	for ( i = 0; i < len; ++i )
		{
		unsigned int d;

		if ( isdigit(s[i]) )
			d = s[i] - '0';

		else if ( s[i] >= 'a' && s[i] < 'a' - 10 + base )
			d = s[i] - 'a' + 10;

		else if ( s[i] >= 'A' && s[i] < 'A' - 10 + base )
			d = s[i] - 'A' + 10;

		else if ( i > 0 )
			break;

		else
			return 0;

		n = n * base + d;
		}

	if ( neg )
		result = -n;
	else
		result = n;

	if ( end )
		*end = s + i;

	return 1;
	}

int strstr_n(const int big_len, const u_char* big,
		const int little_len, const u_char* little)
	{
	if ( little_len > big_len )
		return -1;

	for ( int i = 0; i <= big_len - little_len; ++i )
		{
		if ( ! memcmp(big + i, little, little_len) )
			return i;
		}

	return -1;
	}

int fputs(int len, const char* s, FILE* fp)
	{
	for ( int i = 0; i < len; ++i )
		if ( fputc(s[i], fp) == EOF )
			return EOF;
	return 0;
	}

bool is_printable(const char* s, int len)
	{
	while ( --len >= 0 )
		if ( ! isprint(*s++) )
			return false;
	return true;
	}

const char* fmt_bytes(const char* data, int len)
	{
	static char buf[1024];
	char* p = buf;

	for ( int i = 0; i < len && p - buf < int(sizeof(buf)); ++i )
		{
		if ( isprint(data[i]) )
			*p++ = data[i];
		else
			p += snprintf(p, sizeof(buf) - (p - buf),
					"\\x%02x", (unsigned char) data[i]);
		}

	if ( p - buf < int(sizeof(buf)) )
		*p = '\0';
	else
		buf[sizeof(buf) - 1] = '\0';

	return buf;
	}

const char* fmt(const char* format, ...)
	{
	static char* buf = 0;
	static unsigned int buf_len = 1024;

	if ( ! buf )
		buf = (char*) malloc(buf_len);

	va_list al;
	va_start(al, format);
	int n = safe_vsnprintf(buf, buf_len, format, al);
	va_end(al);

	if ( (unsigned int) n >= buf_len )
		{ // Not enough room, grow the buffer.
		buf_len = n + 32;
		buf = (char*) realloc(buf, buf_len);

		// Is it portable to restart?
		va_start(al, format);
		n = safe_vsnprintf(buf, buf_len, format, al);
		va_end(al);

		if ( (unsigned int) n >= buf_len )
			internal_error("confusion reformatting in fmt()");
		}

	return buf;
	}

const char* fmt_access_time(double t)
	{
	static char buf[256];
	time_t time = (time_t) t;
	strftime(buf, sizeof(buf), "%d/%m-%H:%M", localtime(&time));
	return buf;
	}

bool ensure_dir(const char *dirname)
	{
	struct stat st;
	if ( stat(dirname, &st) < 0 )
		{
		if ( errno != ENOENT )
			{
			warn(fmt("can't stat directory %s: %s",
				dirname, strerror(errno)));
			return false;
			}

		if ( mkdir(dirname, 0700) < 0 )
			{
			warn(fmt("can't create directory %s: %s",
				dirname, strerror(errno)));
			return false;
			}
		}

	else if ( ! S_ISDIR(st.st_mode) )
		{
		warn(fmt("%s exists but is not a directory", dirname));
		return false;
		}

	return true;
	}

bool is_dir(const char* path)
	{
	struct stat st;
	if ( stat(path, &st) < 0 )
		{
		if ( errno != ENOENT )
			warn(fmt("can't stat %s: %s", path, strerror(errno)));

		return false;
		}

	return S_ISDIR(st.st_mode);
	}

void hash_md5(size_t size, const unsigned char* bytes, unsigned char digest[16])
	{
	md5_state_s h;
	md5_init(&h);
	md5_append(&h, bytes, size);
	md5_finish(&h, digest);
	}

const char* md5_digest_print(const unsigned char digest[16])
	{
	static char digest_print[256];

	for ( int i = 0; i < 16; ++i )
		snprintf(digest_print + i * 2, 3, "%02x", digest[i]);

	return digest_print;
	}

int hmac_key_set = 0;
uint8 shared_hmac_md5_key[16];

void hmac_md5(size_t size, const unsigned char* bytes, unsigned char digest[16])
	{
	if ( ! hmac_key_set )
		internal_error("HMAC-MD5 invoked before the HMAC key is set");

	hash_md5(size, bytes, digest);

	for ( int i = 0; i < 16; ++i )
		digest[i] ^= shared_hmac_md5_key[i];

	hash_md5(16, digest, digest);
	}

static bool read_random_seeds(const char* read_file, uint32* seed,
				uint32* buf, int bufsiz)
	{
	struct stat st;
	FILE* f = 0;

	if ( stat(read_file, &st) < 0 )
		{
		warn(fmt("Seed file '%s' does not exist: %s",
				read_file, strerror(errno)));
		return false;
		}

	if ( ! (f = fopen(read_file, "r")) )
		{
		warn(fmt("Could not open seed file '%s': %s",
				read_file, strerror(errno)));
		return false;
		}

	// Read seed for srandom().
	if ( fscanf(f, "%u", seed) != 1 )
		{
		fclose(f);
		return false;
		}

	// Read seeds for MD5.
	for ( int i = 0; i < bufsiz; ++i )
		{
		int tmp;
		if ( fscanf(f, "%u", &tmp) != 1 )
			{
			fclose(f);
			return false;
			}

		buf[i] = tmp;
		}

	fclose(f);
	return true;
	}

static bool write_random_seeds(const char* write_file, uint32 seed,
				uint32* buf, int bufsiz)
	{
	FILE* f = 0;

	if ( ! (f = fopen(write_file, "w+")) )
		{
		warn(fmt("Could not create seed file '%s': %s",
				write_file, strerror(errno)));
		return false;
		}

	fprintf(f, "%u\n", seed);

	for ( int i = 0; i < bufsiz; ++i )
		fprintf(f, "%u\n", buf[i]);

	fclose(f);
	return true;
	}

void init_random_seed(uint32 seed, const char* read_file, const char* write_file)
	{
	static const int bufsiz = 16;
	uint32 buf[bufsiz];
	int pos = 0;	// accumulates entropy
	bool seeds_done = false;

	if ( read_file )
		{
		if ( ! read_random_seeds(read_file, &seed, buf, bufsiz) )
			fprintf(stderr, "Could not load seeds from file '%s'.\n",
					read_file);
		else
			seeds_done = true;
		}

	if ( ! seeds_done )
		{
		// Gather up some entropy.
		gettimeofday((struct timeval *)(buf + pos), 0);
		pos += sizeof(struct timeval) / sizeof(uint32);

#if defined(O_NONBLOCK)
		int fd = open("/dev/random", O_RDONLY | O_NONBLOCK);
#elif defined(O_NDELAY)
		int fd = open("/dev/random", O_RDONLY | O_NDELAY);
#else
		int fd = open("/dev/random", O_RDONLY);
#endif

		if ( fd >= 0 )
			{
			int amt = read(fd, buf + pos,
					sizeof(uint32) * (bufsiz - pos));
			close(fd);

			if ( amt > 0 )
				pos += amt / sizeof(uint32);
			else
				// Clear errno, which can be set on some
				// systems due to a lack of entropy.
				errno = 0;
			}

		if ( pos < bufsiz )
			{
			buf[pos++] = getpid();

			if ( pos < bufsiz )
				buf[pos++] = getuid();
			}

		if ( ! seed )
			{
			for ( int i = 0; i < pos; ++i )
				{
				seed ^= buf[i];
				seed = (seed << 1) | (seed >> 31);
				}
			}
		}

	srandom(seed);

	if ( ! hmac_key_set )
		{
		hash_md5(sizeof(buf), (u_char*) buf, shared_hmac_md5_key);
		hmac_key_set = 1;
		}

	if ( write_file && ! write_random_seeds(write_file, seed, buf, bufsiz) )
		fprintf(stderr, "Could not write seeds to file '%s'.\n",
				write_file);
	}


// Returns a 64-bit random string.
uint64 rand64bit()
	{
	uint64 base = 0;
	int i;

	for ( i = 1; i <= 4; ++i )
		base = (base<<16) | random();
	return base;
	}

void message(const char* msg)
	{
	pinpoint();
	fprintf(stderr, "%s\n", msg);
	}

void warn(const char* msg)
	{
	pinpoint();
	fprintf(stderr, "warning: %s\n", msg);
	++nwarn;
	}

void warn(const char* msg, const char* addl)
	{
	pinpoint();
	fprintf(stderr, "warning: %s %s\n", msg, addl);
	++nwarn;
	}

void error(const char* msg)
	{
	pinpoint();
	fprintf(stderr, "error: %s\n", msg);
	++nerr;
	}

void error(const char* msg, const char* addl)
	{
	pinpoint();
	fprintf(stderr, "error: %s %s\n", msg, addl);
	++nerr;
	}

void error(const char* msg, uint32 addl)
	{
	pinpoint();
	fprintf(stderr, "error: %s - %u\n", msg, addl);
	++nerr;
	}

void run_time(const char* msg)
	{
	pinpoint();
	fprintf(stderr, "run-time error: %s\n", msg);
	++nruntime;
	}

void run_time(const char* fmt, BroObj* obj)
	{
	ODesc d;
	obj->Describe(&d);
	run_time(fmt, d.Description());
	}

void run_time(const char* fmt, const char* arg)
	{
	pinpoint();
	fprintf(stderr, "run-time error: ");
	fprintf(stderr, fmt, arg);
	fprintf(stderr, "\n");
	++nruntime;
	}

void run_time(const char* fmt, const char* arg1, const char* arg2)
	{
	pinpoint();
	fprintf(stderr, "run-time error: ");
	fprintf(stderr, fmt, arg1, arg2);
	fprintf(stderr, "\n");
	++nruntime;
	}

void internal_error(const char* fmt, ...)
	{
	va_list al;

	pinpoint();
	fprintf(stderr, "internal error: ");
	va_start(al, fmt);
	vfprintf(stderr, fmt, al);
	va_end(al);
	fprintf(stderr, "\n");
	set_processing_status("TERMINATED", "internal_error");
	abort();
	}

void pinpoint()
	{
	if ( network_time > 0.0 )
		fprintf(stderr, "%.6f ", network_time);
	else
		{
		if ( filename )
			fprintf(stderr, "%s, ", filename);
		fprintf(stderr, "line %d: ", line_number);
		}
	}

int int_list_cmp(const void* v1, const void* v2)
	{
	ptr_compat_int i1 = *(ptr_compat_int*) v1;
	ptr_compat_int i2 = *(ptr_compat_int*) v2;

	if ( i1 < i2 )
		return -1;
	else if ( i1 == i2 )
		return 0;
	else
		return 1;
	}

const char* bro_path()
	{
	const char* path = getenv("BROPATH");
	if ( ! path )
		path = ".:policy:policy/sigs:policy/time-machine:"
			POLICYDEST ":"
			POLICYDEST "/sigs:" 
			POLICYDEST "/time-machine:"
			POLICYDEST "/site";

	return path;
	}

const char* bro_prefixes()
	{
	int len = 1;	// room for \0
	loop_over_list(prefixes, i)
		len += strlen(prefixes[i]) + 1;

	char* p = new char[len];

	loop_over_list(prefixes, j)
		if ( j == 0 )
			strcpy(p, prefixes[j]);
		else
			{
			strcat(p, ":");
			strcat(p, prefixes[j]);
			}

	return p;
	}

FILE* open_file(const char* filename, const char** full_filename)
	{
	if ( full_filename )
		*full_filename = copy_string(filename);

	FILE* f = fopen(filename, "r");

	return f;
	}

FILE* search_for_file(const char* filename, const char* ext,
			const char** full_filename)
	{
	if ( filename[0] == '/' || filename[0] == '.' )
		return open_file(filename, full_filename);

	char path[1024], full_filename_buf[1024];
	safe_strncpy(path, bro_path(), sizeof(path));

	char* dir_beginning = path;
	char* dir_ending = path;
	int more = *dir_beginning != '\0';

	while ( more )
		{
		while ( *dir_ending && *dir_ending != ':' )
			++dir_ending;

		if ( *dir_ending == ':' )
			*dir_ending = '\0';
		else
			more = 0;

		safe_snprintf(full_filename_buf, sizeof(full_filename_buf),
				"%s/%s.%s", dir_beginning, filename, ext);
		if ( access(full_filename_buf, R_OK) == 0 &&
		     ! is_dir(full_filename_buf) )
			return open_file(full_filename_buf, full_filename);

		safe_snprintf(full_filename_buf, sizeof(full_filename_buf),
				"%s/%s", dir_beginning, filename);
		if ( access(full_filename_buf, R_OK) == 0 &&
		      ! is_dir(full_filename_buf) )
			return open_file(full_filename_buf, full_filename);

		dir_beginning = ++dir_ending;
		}

	if ( full_filename )
		*full_filename = copy_string(filename);

	return 0;
	}

FILE* rotate_file(const char* name, RecordVal* rotate_info)
	{
	// Build file names.
	const int buflen = strlen(name) + 128;

	char tmpname[buflen], newname[buflen+4];

	safe_snprintf(newname, buflen, "%s.%d.%.06f.tmp",
			name, getpid(), network_time);
	newname[buflen-1] = '\0';
	strcpy(tmpname, newname);
	strcat(tmpname, ".tmp");

	// First open the new file using a temporary name.
	FILE* newf = fopen(tmpname, "w");
	if ( ! newf )
		{
		run_time(fmt("rotate_file: can't open %s: %s", tmpname, strerror(errno)));
		return 0;
		}

	// Then move old file to "<name>.<pid>.<timestamp>" and make sure
	// it really gets created.
	struct stat dummy;
	if ( link(name, newname) < 0 || stat(newname, &dummy) < 0 )
		{
		run_time(fmt("rotate_file: can't move %s to %s: %s", name, newname, strerror(errno)));
		fclose(newf);
		unlink(newname);
		unlink(tmpname);
		return 0;
		}

	// Close current file, and move the tmp to its place.
	if ( unlink(name) < 0 || link(tmpname, name) < 0 || unlink(tmpname) < 0 )
		{
		run_time(fmt("rotate_file: can't move %s to %s: %s", tmpname, name, strerror(errno)));
		exit(1);	// hard to fix, but shouldn't happen anyway...
		}

	// Init rotate_info.
	if ( rotate_info )
		{
		rotate_info->Assign(0, new StringVal(name));
		rotate_info->Assign(1, new StringVal(newname));
		rotate_info->Assign(2, new Val(network_time, TYPE_TIME));
		rotate_info->Assign(3, new Val(network_time, TYPE_TIME));
		}

	return newf;
	}

const char* log_file_name(const char* tag)
	{
	const char* env = getenv("BRO_LOG_SUFFIX");
	return fmt("%s.%s", tag, (env ? env : "log"));
	}

double calc_next_rotate(double interval, const char* rotate_base_time)
	{
	double current = network_time;

	// Calculate start of day.
	time_t teatime = time_t(current);

	struct tm t;
	t = *localtime(&teatime);
	t.tm_hour = t.tm_min = t.tm_sec = 0;
	double startofday = mktime(&t);

	double base = -1;

	if ( rotate_base_time && rotate_base_time[0] != '\0' )
		{
		struct tm t;
		if ( ! strptime(rotate_base_time, "%H:%M", &t) )
			run_time("calc_next_rotate(): can't parse rotation base time");
		else
			base = t.tm_min * 60 + t.tm_hour * 60 * 60;
		}

	if ( base < 0 )
		// No base time given. To get nice timestamps, we round
		// the time up to the next multiple of the rotation interval.
		return floor(current / interval) * interval
			+ interval - current;

	// current < startofday + base + i * interval <= current + interval
	return startofday + base +
		ceil((current - startofday - base) / interval) * interval -
			current;
	}


RETSIGTYPE sig_handler(int signo);

void terminate_processing()
	{
	if ( ! terminating )
		sig_handler(SIGTERM);
	}

extern const char* proc_status_file;
void _set_processing_status(const char* status)
	{
	if ( ! proc_status_file )
		return;

	// This function can be called from a signal context, so we have to
	// make sure to only call reentrant functions and to restore errno
	// afterwards.

	int old_errno = errno;

	int fd = open(proc_status_file, O_CREAT | O_WRONLY | O_TRUNC, 0700);

	int len = strlen(status);
	while ( len )
		{
		int n = write(fd, status, len);

		if ( n < 0 && errno != EINTR && errno != EAGAIN )
			// Ignore errors, as they're too difficult to
			// safely report here.
			break;

		status += n;
		len -= n;
		}

	close(fd);

	errno = old_errno;
	}

double current_time(bool real)
	{
	struct timeval tv;
	if ( gettimeofday(&tv, 0) < 0 )
		internal_error("gettimeofday failed in current_time()");

	double t = double(tv.tv_sec) + double(tv.tv_usec) / 1e6;

	if ( ! pseudo_realtime || real || pkt_srcs.length() == 0 )
		return t;

	// This obviously only works for a single source ...
	PktSrc* src = pkt_srcs[0];

	if ( net_is_processing_suspended() )
		return src->CurrentPacketTimestamp();

	// We don't scale with pseudo_realtime here as that would give us a
	// jumping real-time.
	return src->CurrentPacketTimestamp() +
		(t - src->CurrentPacketWallClock());
	}

struct timeval double_to_timeval(double t)
	{
	struct timeval tv;

	double t1 = floor(t);
	tv.tv_sec = int(t1);
	tv.tv_usec = int((t - t1) * 1e6 + 0.5);

	return tv;
	}

int time_compare(struct timeval* tv_a, struct timeval* tv_b)
	{
	if ( tv_a->tv_sec == tv_b->tv_sec )
		return tv_a->tv_usec - tv_b->tv_usec;
	else
		return tv_a->tv_sec - tv_b->tv_sec;
	}

void out_of_memory(const char* where)
	{
	fprintf( stderr, "bro: out of memory in %s.\n", where );
	abort();
	}

void get_memory_usage(unsigned int* total, unsigned int* malloced)
	{
	unsigned int ret_total;

#ifdef HAVE_MALLINFO
	// For memory, getrusage() gives bogus results on Linux. Grmpf.
	struct mallinfo mi = mallinfo();

	if ( malloced )
		*malloced = mi.uordblks;

	ret_total = mi.arena;

	if ( total )
		*total = ret_total;
#else
	struct rusage r;
	getrusage(RUSAGE_SELF, &r);

	if ( malloced )
		*malloced = 0;

	// At least on FreeBSD it's in KB.
	ret_total = r.ru_maxrss * 1024;

	if ( total )
		*total = ret_total;
#endif

	// return ret_total;
	}

#ifdef malloc

#undef malloc
#undef realloc
#undef free

extern "C" {
void* malloc(size_t);
void* realloc(void*, size_t);
void free(void*);
}

static int malloc_debug = 0;

void* debug_malloc(size_t t)
	{
	void* v = malloc(t);
	if ( malloc_debug )
		printf("%.6f malloc %x %d\n", network_time, v, t);
	return v;
	}

void* debug_realloc(void* v, size_t t)
	{
	v = realloc(v, t);
	if ( malloc_debug )
		printf("%.6f realloc %x %d\n", network_time, v, t);
	return v;
	}

void debug_free(void* v)
	{
	if ( malloc_debug )
		printf("%.6f free %x\n", network_time, v);
	free(v);
	}

void* operator new(size_t t)
	{
	void* v = malloc(t);
	if ( malloc_debug )
		printf("%.6f new %x %d\n", network_time, v, t);
	return v;
	}

void* operator new[](size_t t)
	{
	void* v = malloc(t);
	if ( malloc_debug )
		printf("%.6f new[] %x %d\n", network_time, v, t);
	return v;
	}

void operator delete(void* v)
	{
	if ( malloc_debug )
		printf("%.6f delete %x\n", network_time, v);
	free(v);
	}

void operator delete[](void* v)
	{
	if ( malloc_debug )
		printf("%.6f delete %x\n", network_time, v);
	free(v);
	}

#endif
