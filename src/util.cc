// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "util-config.h"

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

#ifdef HAVE_DARWIN
#include <mach/task.h>
#include <mach/mach_init.h>
#endif

#include <string>
#include <array>
#include <vector>
#include <algorithm>
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
#include <libgen.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#ifdef HAVE_MALLINFO
# include <malloc.h>
#endif

#include "digest.h"
#include "input.h"
#include "util.h"
#include "Obj.h"
#include "Val.h"
#include "NetVar.h"
#include "Net.h"
#include "Reporter.h"
#include "iosource/Manager.h"

/**
 * Return IP address without enclosing brackets and any leading 0x.
 */
std::string extract_ip(const std::string& i)
	{
	std::string s(skip_whitespace(i.c_str()));
	if ( s.size() > 0 && s[0] == '[' )
		s.erase(0, 1);

	if ( s.size() > 1 && s.substr(0, 2) == "0x" )
		s.erase(0, 2);

	size_t pos = 0;
	if ( (pos = s.find(']')) != std::string::npos )
		s = s.substr(0, pos);

	return s;
	}

/**
 * Given a subnet string, return IP address and subnet length separately.
 */
std::string extract_ip_and_len(const std::string& i, int* len)
	{
	size_t pos = i.find('/');
	if ( pos == std::string::npos )
		return i;

	if ( len )
		*len = atoi(i.substr(pos + 1).c_str());

	return extract_ip(i.substr(0, pos));
	}

/**
 * Takes a string, unescapes all characters that are escaped as hex codes
 * (\x##) and turns them into the equivalent ascii-codes. Returns a string
 * containing no escaped values
 *
 * @param str string to unescape
 * @return A str::string without escaped characters.
 */
std::string get_unescaped_string(const std::string& arg_str)
	{
	const char* str = arg_str.c_str();
	char* buf = new char [arg_str.length() + 1]; // it will at most have the same length as str.
	char* bufpos = buf;
	size_t pos = 0;

	while ( pos < arg_str.length() )
		{
		if ( str[pos] == '\\' && str[pos+1] == 'x' &&
		     isxdigit(str[pos+2]) && isxdigit(str[pos+3]) )
			{
				*bufpos = (decode_hex(str[pos+2]) << 4) +
					decode_hex(str[pos+3]);

				pos += 4;
				bufpos++;
			}
		else
			*bufpos++ = str[pos++];
		}

	*bufpos = 0;
	string outstring(buf, bufpos - buf);

	delete [] buf;

	return outstring;
	}

/**
 * Takes a string, escapes characters into equivalent hex codes (\x##), and
 * returns a string containing all escaped values.
 *
 * @param d an ODesc object to store the escaped hex version of the string,
 *          if null one will be allocated and returned from the function.
 * @param str string to escape
 * @param escape_all If true, all characters are escaped. If false, only
 * characters are escaped that are either whitespace or not printable in
 * ASCII.
 * @return A ODesc object containing a list of escaped hex values of the form
 *         \x##, which may be newly allocated if \a d was a null pointer. */
ODesc* get_escaped_string(ODesc* d, const char* str, size_t len,
                          bool escape_all)
	{
	if ( ! d )
		d = new ODesc();

	for ( size_t i = 0; i < len; ++i )
		{
		char c = str[i];

		if ( escape_all || isspace(c) || ! isascii(c) || ! isprint(c) )
			{
			if ( c == '\\' )
				d->AddRaw("\\\\", 2);
			else
				{
				char hex[4] = {'\\', 'x', '0', '0' };
				bytetohex(c, hex + 2);
				d->AddRaw(hex, 4);
				}
			}

		else
			d->AddRaw(&c, 1);
		}

	return d;
	}

std::string get_escaped_string(const char* str, size_t len, bool escape_all)
	{
	ODesc d;
	return get_escaped_string(&d, str, len, escape_all)->Description();
	}

char* copy_string(const char* s)
	{
	if ( ! s )
		return 0;

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
			reporter->Warning("bad octal escape: %s ", start);
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
			reporter->Warning("bad hexadecimal escape: %s", start);
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

string to_upper(const std::string& s)
	{
	string t = s;
	std::transform(t.begin(), t.end(), t.begin(), ::toupper);
	return t;
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

	if  ( h < 0 || h > 15 )
		{
		reporter->InternalWarning("illegal value for encode_hex: %d", h);
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
		} while ( strncasecmp(s, find, len) != 0 );

		--s;
		}

	return (char*) s;
	}
#endif

template<class T> int atoi_n(int len, const char* s, const char** end, int base, T& result)
	{
	T n = 0;
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

// Instantiate the ones we need.
template int atoi_n<int>(int len, const char* s, const char** end, int base, int& result);
template int atoi_n<uint16_t>(int len, const char* s, const char** end, int base, uint16_t& result);
template int atoi_n<uint32_t>(int len, const char* s, const char** end, int base, uint32_t& result);
template int atoi_n<int64_t>(int len, const char* s, const char** end, int base, int64_t& result);
template int atoi_n<uint64_t>(int len, const char* s, const char** end, int base, uint64_t& result);

char* uitoa_n(uint64 value, char* str, int n, int base, const char* prefix)
	{
	static char dig[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

	assert(n);

	int i = 0;
	uint64 v;
	char* p, *q;
	char c;

	if ( prefix )
		{
		strncpy(str, prefix, n);
		str[n-1] = '\0';
		i += strlen(prefix);
		}

	if ( i >= n - 1 )
		return str;

	v = value;

	do {
		str[i++] = dig[v % base];
		v /= base;
	} while ( v && i < n - 1 );

	str[i] = '\0';

	return str;
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

std::string strtolower(const std::string& s)
	{
	std::string t = s;
	std::transform(t.begin(), t.end(), t.begin(), ::tolower);
	return t;
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

const char* fmt(const char* format, va_list al)
	{
	static char* buf = 0;
	static unsigned int buf_len = 1024;

	if ( ! buf )
		buf = (char*) safe_malloc(buf_len);

	va_list alc;
	va_copy(alc, al);
	int n = safe_vsnprintf(buf, buf_len, format, al);

	if ( (unsigned int) n >= buf_len )
		{ // Not enough room, grow the buffer.
		buf_len = n + 32;
		buf = (char*) safe_realloc(buf, buf_len);

		n = safe_vsnprintf(buf, buf_len, format, alc);

		if ( (unsigned int) n >= buf_len )
			reporter->InternalError("confusion reformatting in fmt()");
		}

	va_end(alc);
	return buf;
	}

const char* fmt(const char* format, ...)
	{
	va_list al;
	va_start(al, format);
	auto rval = fmt(format, al);
	va_end(al);
	return rval;
	}

const char* fmt_access_time(double t)
	{
	static char buf[256];
	time_t time = (time_t) t;
	struct tm ts;

	if ( ! localtime_r(&time, &ts) )
		{
		reporter->InternalError("unable to get time");
		}

	strftime(buf, sizeof(buf), "%d/%m-%H:%M", &ts);
	return buf;
	}

bool ensure_intermediate_dirs(const char* dirname)
	{
	if ( ! dirname || strlen(dirname) == 0 )
		return false;

	bool absolute = dirname[0] == '/';
	string path = normalize_path(dirname);

	vector<string> path_components;
	tokenize_string(path, "/", &path_components);

	string current_dir;

	for ( size_t i = 0; i < path_components.size(); ++i )
		{
		if ( i > 0 || absolute )
			current_dir += "/";

		current_dir += path_components[i];

		if ( ! ensure_dir(current_dir.c_str()) )
			return false;
		}

	return true;
	}

bool ensure_dir(const char *dirname)
	{
	struct stat st;
	if ( stat(dirname, &st) < 0 )
		{
		if ( errno != ENOENT )
			{
			reporter->Warning("can't stat directory %s: %s",
				dirname, strerror(errno));
			return false;
			}

		if ( mkdir(dirname, 0700) < 0 )
			{
			reporter->Warning("can't create directory %s: %s",
				dirname, strerror(errno));
			return false;
			}
		}

	else if ( ! S_ISDIR(st.st_mode) )
		{
		reporter->Warning("%s exists but is not a directory", dirname);
		return false;
		}

	return true;
	}

bool is_dir(const std::string& path)
	{
	struct stat st;
	if ( stat(path.c_str(), &st) < 0 )
		{
		if ( errno != ENOENT )
			reporter->Warning("can't stat %s: %s", path.c_str(), strerror(errno));

		return false;
		}

	return S_ISDIR(st.st_mode);
	}

bool is_file(const std::string& path)
	{
	struct stat st;
	if ( stat(path.c_str(), &st) < 0 )
		{
		if ( errno != ENOENT )
			reporter->Warning("can't stat %s: %s", path.c_str(), strerror(errno));

		return false;
		}

	return S_ISREG(st.st_mode);
	}

string strreplace(const string& s, const string& o, const string& n)
	{
	string r = s;

	while ( true )
		{
		size_t i = r.find(o);

		if ( i == std::string::npos )
			break;

		r.replace(i, o.size(), n);
		}

	return r;
}

std::string strstrip(std::string s)
	{
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
	s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
	return s;
	}

bool hmac_key_set = false;
uint8 shared_hmac_md5_key[16];

bool siphash_key_set = false;
uint8 shared_siphash_key[SIPHASH_KEYLEN];

void hmac_md5(size_t size, const unsigned char* bytes, unsigned char digest[16])
	{
	if ( ! hmac_key_set )
		reporter->InternalError("HMAC-MD5 invoked before the HMAC key is set");

	internal_md5(bytes, size, digest);

	for ( int i = 0; i < 16; ++i )
		digest[i] ^= shared_hmac_md5_key[i];

	internal_md5(digest, 16, digest);
	}

static bool read_random_seeds(const char* read_file, uint32* seed,
				uint32* buf, int bufsiz)
	{
	FILE* f = 0;

	if ( ! (f = fopen(read_file, "r")) )
		{
		reporter->Warning("Could not open seed file '%s': %s",
				read_file, strerror(errno));
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
		reporter->Warning("Could not create seed file '%s': %s",
				write_file, strerror(errno));
		return false;
		}

	fprintf(f, "%u\n", seed);

	for ( int i = 0; i < bufsiz; ++i )
		fprintf(f, "%u\n", buf[i]);

	fclose(f);
	return true;
	}

static bool bro_rand_determistic = false;
static unsigned int bro_rand_state = 0;
static bool first_seed_saved = false;
static unsigned int first_seed = 0;

static void bro_srandom(unsigned int seed, bool deterministic)
	{
	bro_rand_state = seed;
	bro_rand_determistic = deterministic;

	srandom(seed);
	}

void bro_srandom(unsigned int seed)
	{
	if ( bro_rand_determistic )
		bro_rand_state = seed;
	else
		srandom(seed);
	}

void init_random_seed(const char* read_file, const char* write_file)
	{
	static const int bufsiz = 20;
	uint32 buf[bufsiz];
	memset(buf, 0, sizeof(buf));
	int pos = 0;	// accumulates entropy
	bool seeds_done = false;
	uint32 seed = 0;

	if ( read_file )
		{
		if ( ! read_random_seeds(read_file, &seed, buf, bufsiz) )
			reporter->FatalError("Could not load seeds from file '%s'.\n",
					     read_file);
		else
			seeds_done = true;
		}

	if ( ! seeds_done )
		{
		// Gather up some entropy.
		gettimeofday((struct timeval *)(buf + pos), 0);
		pos += sizeof(struct timeval) / sizeof(uint32);

		// use urandom. For reasons see e.g. http://www.2uo.de/myths-about-urandom/
#if defined(O_NONBLOCK)
		int fd = open("/dev/urandom", O_RDONLY | O_NONBLOCK);
#elif defined(O_NDELAY)
		int fd = open("/dev/urandom", O_RDONLY | O_NDELAY);
#else
		int fd = open("/dev/urandom", O_RDONLY);
#endif

		if ( fd >= 0 )
			{
			int amt = read(fd, buf + pos,
					sizeof(uint32) * (bufsiz - pos));
			safe_close(fd);

			if ( amt > 0 )
				pos += amt / sizeof(uint32);
			else
				// Clear errno, which can be set on some
				// systems due to a lack of entropy.
				errno = 0;
			}

		if ( pos < bufsiz )
			reporter->FatalError("Could not read enough random data from /dev/urandom. Wanted %d, got %d", bufsiz, pos);

		if ( ! seed )
			{
			for ( int i = 0; i < pos; ++i )
				{
				seed ^= buf[i];
				seed = (seed << 1) | (seed >> 31);
				}
			}
		else
			seeds_done = true;
		}

	bro_srandom(seed, seeds_done);

	if ( ! first_seed_saved )
		{
		first_seed = seed;
		first_seed_saved = true;
		}

	if ( ! hmac_key_set )
		{
		assert(sizeof(buf) - 16 == 64);
		internal_md5((const u_char*) buf, sizeof(buf) - 16, shared_hmac_md5_key); // The last 128 bits of buf are for siphash
		hmac_key_set = true;
		}

	if ( ! siphash_key_set )
		{
		assert(sizeof(buf) - 64 == SIPHASH_KEYLEN);
		memcpy(shared_siphash_key, reinterpret_cast<const char*>(buf) + 64, SIPHASH_KEYLEN);
		siphash_key_set = true;
		}

	if ( write_file && ! write_random_seeds(write_file, seed, buf, bufsiz) )
		reporter->Error("Could not write seeds to file '%s'.\n",
				write_file);
	}

unsigned int initial_seed()
	{
	return first_seed;
	}

bool have_random_seed()
	{
	return bro_rand_determistic;
	}

unsigned int bro_prng(unsigned int  state)
	{
	// Use our own simple linear congruence PRNG to make sure we are
	// predictable across platforms.
	static const long int m = 2147483647;
	static const long int a = 16807;
	const long int q = m / a;
	const long int r = m % a;

	state = a * ( state % q ) - r * ( state / q );

	if ( state <= 0 )
		state += m;

	return state;
	}

long int bro_random()
	{
	if ( ! bro_rand_determistic )
		return random(); // Use system PRNG.

	bro_rand_state = bro_prng(bro_rand_state);

	return bro_rand_state;
	}

// Returns a 64-bit random string.
uint64 rand64bit()
	{
	uint64 base = 0;
	int i;

	for ( i = 1; i <= 4; ++i )
		base = (base<<16) | bro_random();
	return base;
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

static string bro_path_value;

const std::string& bro_path()
	{
	if ( bro_path_value.empty() )
		{
		const char* path = getenv("BROPATH");

		if ( ! path )
			path = DEFAULT_BROPATH;

		bro_path_value = path;
		}

	return bro_path_value;
	}

extern void add_to_bro_path(const string& dir)
	{
	// Make sure path is initialized.
	bro_path();

	bro_path_value += string(":") + dir;
	}

const char* bro_plugin_path()
	{
	const char* path = getenv("BRO_PLUGIN_PATH");

	if ( ! path )
		path = BRO_PLUGIN_INSTALL_PATH;

	return path;
	}

const char* bro_plugin_activate()
	{
	const char* names = getenv("BRO_PLUGIN_ACTIVATE");

	if ( ! names )
		names = "";

	return names;
	}

string bro_prefixes()
	{
	string rval;

	loop_over_list(prefixes, j)
		if ( j == 0 )
			rval.append(prefixes[j]);
		else
			rval.append(":").append(prefixes[j]);

	return rval;
	}

const array<string, 2> script_extensions = {".zeek", ".bro"};

bool is_package_loader(const string& path)
	{
	string filename(std::move(SafeBasename(path).result));

	for ( const string& ext : script_extensions )
		{
		if ( filename == "__load__" + ext )
			return true;
		}

	return false;
	}

FILE* open_file(const string& path, const string& mode)
	{
	if ( path.empty() )
		return 0;

	FILE* rval = fopen(path.c_str(), mode.c_str());

	if ( ! rval )
		{
		char buf[256];
		bro_strerror_r(errno, buf, sizeof(buf));
		reporter->Error("Failed to open file %s: %s", filename, buf);
		}

	return rval;
	}

static bool can_read(const string& path)
	{
	return access(path.c_str(), R_OK) == 0;
	}

FILE* open_package(string& path, const string& mode)
	{
	string arg_path = path;
	path.append("/__load__");

	for ( const string& ext : script_extensions )
		{
		string p = path + ext;
		if ( can_read(p) )
			{
			path.append(ext);
			return open_file(path, mode);
			}
		}

	path.append(script_extensions[0]);
	string package_loader = "__load__" + script_extensions[0];
	reporter->Error("Failed to open package '%s': missing '%s' file",
	                arg_path.c_str(), package_loader.c_str());
	return 0;
	}

void SafePathOp::CheckValid(const char* op_result, const char* path,
                            bool error_aborts)
	{
	if ( op_result )
		{
		result = op_result;
		error = false;
		}
	else
		{
		if ( error_aborts )
			reporter->InternalError("Path operation failed on %s: %s",
			                        path ? path : "<null>", strerror(errno));
		else
			error = true;
		}
	}

SafeDirname::SafeDirname(const char* path, bool error_aborts)
	: SafePathOp()
	{
	DoFunc(path ? path : "", error_aborts);
	}

SafeDirname::SafeDirname(const string& path, bool error_aborts)
	: SafePathOp()
	{
	DoFunc(path, error_aborts);
	}

void SafeDirname::DoFunc(const string& path, bool error_aborts)
	{
	char* tmp = copy_string(path.c_str());
	CheckValid(dirname(tmp), tmp, error_aborts);
	delete [] tmp;
	}

SafeBasename::SafeBasename(const char* path, bool error_aborts)
	: SafePathOp()
	{
	DoFunc(path ? path : "", error_aborts);
	}

SafeBasename::SafeBasename(const string& path, bool error_aborts)
	: SafePathOp()
	{
	DoFunc(path, error_aborts);
	}

void SafeBasename::DoFunc(const string& path, bool error_aborts)
	{
	char* tmp = copy_string(path.c_str());
	CheckValid(basename(tmp), tmp, error_aborts);
	delete [] tmp;
	}

string implode_string_vector(const std::vector<std::string>& v,
                             const std::string& delim)
	{
	string rval;

	for ( size_t i = 0; i < v.size(); ++i )
		{
		if ( i > 0 )
			rval += delim;

		rval += v[i];
		}

	return rval;
	}

string flatten_script_name(const string& name, const string& prefix)
	{
	string rval = prefix;

	if ( ! rval.empty() )
		rval.append(".");

	if ( is_package_loader(name) )
		rval.append(SafeDirname(name).result);
	else
		rval.append(name);

	size_t i;

	while ( (i = rval.find('/')) != string::npos )
		rval[i] = '.';

	return rval;
	}

vector<string>* tokenize_string(string input, const string& delim,
                                vector<string>* rval)
	{
	if ( ! rval )
		rval = new vector<string>();

	size_t n;

	while ( (n = input.find(delim)) != string::npos )
		{
		rval->push_back(input.substr(0, n));
		input.erase(0, n + 1);
		}

	rval->push_back(input);
	return rval;
	}


string normalize_path(const string& path)
	{
	size_t n;
	vector<string> components, final_components;
	string new_path;

	if ( path[0] == '/' )
		new_path = "/";

	tokenize_string(path, "/", &components);

	vector<string>::const_iterator it;
	for ( it = components.begin(); it != components.end(); ++it )
		{
		if ( *it == "" ) continue;
		final_components.push_back(*it);

		if ( *it == "." && it != components.begin() )
			final_components.pop_back();
		else if ( *it == ".." && final_components[0] != ".." )
			{
			final_components.pop_back();
			final_components.pop_back();
			}
		}

	for ( it = final_components.begin(); it != final_components.end(); ++it )
		{
		new_path.append(*it);
		new_path.append("/");
		}

	if ( new_path.size() > 1 && new_path[new_path.size() - 1] == '/' )
		new_path.erase(new_path.size() - 1);

	return new_path;
	}

string without_bropath_component(const string& path)
	{
	string rval = normalize_path(path);

	vector<string> paths;
	tokenize_string(bro_path(), ":", &paths);

	for ( size_t i = 0; i < paths.size(); ++i )
		{
		string common = normalize_path(paths[i]);

		if ( rval.find(common) != 0 )
			continue;

		// Found the containing directory.
		rval.erase(0, common.size());

		// Remove leading path separators.
		while ( rval.size() && rval[0] == '/' )
			rval.erase(0, 1);

		return rval;
		}

	return rval;
	}

static string find_file_in_path(const string& filename, const string& path,
                                const vector<string>& opt_ext)
	{
	if ( filename.empty() )
		return string();

	// If file name is an absolute path, searching within *path* is pointless.
	if ( filename[0] == '/' )
		{
		if ( can_read(filename) )
			return filename;
		else
			return string();
		}

	string abs_path = path + '/' + filename;

	if ( ! opt_ext.empty() )
		{
		for ( const string& ext : opt_ext )
			{
			string with_ext = abs_path + ext;

			if ( can_read(with_ext) )
				return with_ext;
			}
		}

	if ( can_read(abs_path) )
		return abs_path;

	return string();
	}

string find_file(const string& filename, const string& path_set,
                 const string& opt_ext)
	{
	vector<string> paths;
	tokenize_string(path_set, ":", &paths);

	vector<string> ext;
	if ( ! opt_ext.empty() )
		ext.push_back(opt_ext);

	for ( size_t n = 0; n < paths.size(); ++n )
		{
		string f = find_file_in_path(filename, paths[n], ext);

		if ( ! f.empty() )
			return f;
		}

	return string();
	}

static bool ends_with(const std::string& s, const std::string& ending)
	{
	if ( ending.size() > s.size() )
		return false;

	return std::equal(ending.rbegin(), ending.rend(), s.rbegin());
	}

string find_script_file(const string& filename, const string& path_set)
	{
	vector<string> paths;
	tokenize_string(path_set, ":", &paths);

	vector<string> ext(script_extensions.begin(), script_extensions.end());

	for ( size_t n = 0; n < paths.size(); ++n )
		{
		string f = find_file_in_path(filename, paths[n], ext);

		if ( ! f.empty() )
			return f;
		}

	if ( ends_with(filename, ".bro") )
		{
		// We were looking for a file explicitly ending in .bro and didn't
		// find it, so fall back to one ending in .zeek, if it exists.
		auto fallback = string(filename.data(), filename.size() - 4) + ".zeek";
		return find_script_file(fallback, path_set);
		}

	return string();
	}

FILE* rotate_file(const char* name, RecordVal* rotate_info)
	{
	// Build file names.
	const int buflen = strlen(name) + 128;

	char newname[buflen], tmpname[buflen+4];

	safe_snprintf(newname, buflen, "%s.%d.%.06f.tmp",
			name, getpid(), network_time);
	newname[buflen-1] = '\0';
	strcpy(tmpname, newname);
	strcat(tmpname, ".tmp");

	// First open the new file using a temporary name.
	FILE* newf = fopen(tmpname, "w");
	if ( ! newf )
		{
		reporter->Error("rotate_file: can't open %s: %s", tmpname, strerror(errno));
		return 0;
		}

	// Then move old file to "<name>.<pid>.<timestamp>" and make sure
	// it really gets created.
	struct stat dummy;
	if ( link(name, newname) < 0 || stat(newname, &dummy) < 0 )
		{
		reporter->Error("rotate_file: can't move %s to %s: %s", name, newname, strerror(errno));
		fclose(newf);
		unlink(newname);
		unlink(tmpname);
		return 0;
		}

	// Close current file, and move the tmp to its place.
	if ( unlink(name) < 0 || link(tmpname, name) < 0 || unlink(tmpname) < 0 )
		{
		reporter->Error("rotate_file: can't move %s to %s: %s", tmpname, name, strerror(errno));
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

double parse_rotate_base_time(const char* rotate_base_time)
	{
	double base = -1;

	if ( rotate_base_time && rotate_base_time[0] != '\0' )
		{
		struct tm t;
		if ( ! strptime(rotate_base_time, "%H:%M", &t) )
			reporter->Error("calc_next_rotate(): can't parse rotation base time");
		else
			base = t.tm_min * 60 + t.tm_hour * 60 * 60;
		}

	return base;
	}

double calc_next_rotate(double current, double interval, double base)
	{
	if ( ! interval )
		{
		reporter->Error("calc_next_rotate(): interval is zero, falling back to 24hrs");
		interval = 86400;
		}

	// Calculate start of day.
	time_t teatime = time_t(current);

	struct tm t;
	if ( ! localtime_r(&teatime, &t) )
		{
		reporter->Error("calc_next_rotate(): failure processing current time (%.6f)", current);

		// fall back to the method used if no base time is given
		base = -1;
		}

	if ( base < 0 )
		// No base time given. To get nice timestamps, we round
		// the time up to the next multiple of the rotation interval.
		return floor(current / interval) * interval
			+ interval - current;

	t.tm_hour = t.tm_min = t.tm_sec = 0;
	double startofday = mktime(&t);

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

	if ( fd < 0 )
		{
		char buf[256];
		bro_strerror_r(errno, buf, sizeof(buf));
		if ( reporter )
			reporter->Error("Failed to open process status file '%s': %s",
			                proc_status_file, buf);
		else
			fprintf(stderr, "Failed to open process status file '%s': %s\n",
			                proc_status_file, buf);
		errno = old_errno;
		return;
		}

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

	safe_close(fd);

	errno = old_errno;
	}

double current_time(bool real)
	{
	struct timeval tv;
	if ( gettimeofday(&tv, 0) < 0 )
		reporter->InternalError("gettimeofday failed in current_time()");

	double t = double(tv.tv_sec) + double(tv.tv_usec) / 1e6;

	const iosource::Manager::PktSrcList& pkt_srcs(iosource_mgr->GetPktSrcs());

	if ( ! pseudo_realtime || real || pkt_srcs.empty() )
		return t;

	// This obviously only works for a single source ...
	iosource::PktSrc* src = pkt_srcs.front();

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

struct UIDEntry {
	UIDEntry() : key(0, 0), needs_init(true) { }
	UIDEntry(const uint64 i) : key(i, 0), needs_init(false) { }

	struct UIDKey {
		UIDKey(uint64 i, uint64 c) : instance(i), counter(c) { }
		uint64 instance;
		uint64 counter;
	} key;

	bool needs_init;
};

static std::vector<UIDEntry> uid_pool;

uint64 calculate_unique_id()
	{
	return calculate_unique_id(UID_POOL_DEFAULT_INTERNAL);
	}

uint64 calculate_unique_id(size_t pool)
	{
	uint64 uid_instance = 0;

	if( pool >= uid_pool.size() )
		{
		if ( pool < 10000 )
			uid_pool.resize(pool + 1);
		else
			{
			reporter->Warning("pool passed to calculate_unique_id() too large, using default");
			pool = UID_POOL_DEFAULT_INTERNAL;
			}
		}

	if ( uid_pool[pool].needs_init )
		{
		// This is the first time we need a UID for this pool.
		if ( ! have_random_seed() )
			{
			// If we don't need deterministic output (as
			// indicated by a set seed), we calculate the
			// instance ID by hashing something likely to be
			// globally unique.
			struct {
				char hostname[120];
				uint64 pool;
				struct timeval time;
				pid_t pid;
				int rnd;
			} unique;

			memset(&unique, 0, sizeof(unique)); // Make valgrind happy.
			gethostname(unique.hostname, 120);
			unique.hostname[sizeof(unique.hostname)-1] = '\0';
			gettimeofday(&unique.time, 0);
			unique.pool = (uint64) pool;
			unique.pid = getpid();
			unique.rnd = bro_random();

			uid_instance = HashKey::HashBytes(&unique, sizeof(unique));
			++uid_instance; // Now it's larger than zero.
			}
		else
			// Generate determistic UIDs for each individual pool.
			uid_instance = pool;

		// Our instance is unique.  Huzzah.
		uid_pool[pool] = UIDEntry(uid_instance);
		}

	assert(!uid_pool[pool].needs_init);
	assert(uid_pool[pool].key.instance != 0);

	++uid_pool[pool].key.counter;
	return HashKey::HashBytes(&(uid_pool[pool].key), sizeof(uid_pool[pool].key));
	}

bool safe_write(int fd, const char* data, int len)
	{
	while ( len > 0 )
		{
		int n = write(fd, data, len);

		if ( n < 0 )
			{
			if ( errno == EINTR )
				continue;

			fprintf(stderr, "safe_write error: %d\n", errno);
			abort();

			return false;
			}

		data += n;
		len -= n;
		}

	return true;
	}

bool safe_pwrite(int fd, const unsigned char* data, size_t len, size_t offset)
	{
	while ( len != 0 )
		{
		ssize_t n = pwrite(fd, data, len, offset);

		if ( n < 0 )
			{
			if ( errno == EINTR )
				continue;

			fprintf(stderr, "safe_write error: %d\n", errno);
			abort();

			return false;
			}

		data += n;
		offset +=n;
		len -= n;
		}

	return true;
	}

void safe_close(int fd)
	{
	/*
	 * Failure cases of close(2) are ...
	 * EBADF: Indicative of programming logic error that needs to be fixed, we
	 *        should always be attempting to close a valid file descriptor.
	 * EINTR: Ignore signal interruptions, most implementations will actually
	 *        reclaim the open descriptor and POSIX standard doesn't leave many
	 *        options by declaring the state of the descriptor as "unspecified".
	 *        Attempting to inspect actual state or re-attempt close() is not
	 *        thread safe.
	 * EIO:   Again the state of descriptor is "unspecified", but don't recover
	 *        from an I/O error, safe_write() won't either.
	 *
	 * Note that we don't use the reporter here to allow use from different threads.
	 */
	if ( close(fd) < 0 && errno != EINTR )
		{
		char buf[128];
		bro_strerror_r(errno, buf, sizeof(buf));
		fprintf(stderr, "safe_close error %d: %s\n", errno, buf);
		abort();
		}
	}

extern "C" void out_of_memory(const char* where)
	{
	fprintf(stderr, "out of memory in %s.\n", where);

	if ( reporter )
		// Guess that might fail here if memory is really tight ...
		reporter->FatalError("out of memory in %s.\n", where);

	abort();
	}

void get_memory_usage(uint64* total, uint64* malloced)
	{
	uint64 ret_total;

#ifdef HAVE_MALLINFO
	struct mallinfo mi = mallinfo();

	if ( malloced )
		*malloced = mi.uordblks;
#endif

#ifdef HAVE_DARWIN
	struct mach_task_basic_info t_info;
	mach_msg_type_number_t t_info_count = MACH_TASK_BASIC_INFO;

	if ( KERN_SUCCESS != task_info(mach_task_self(),
	                               MACH_TASK_BASIC_INFO,
	                               (task_info_t)&t_info,
	                               &t_info_count) )
		ret_total = 0;
	else
		ret_total = t_info.resident_size;
#else
	struct rusage r;
	getrusage(RUSAGE_SELF, &r);

	// In KB.
	ret_total = r.ru_maxrss * 1024;
#endif

	if ( total )
		*total = ret_total;
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

std::string canonify_name(const std::string& name)
	{
	unsigned int len = name.size();
	std::string nname;

	for ( unsigned int i = 0; i < len; i++ )
		{
		char c = isalnum(name[i]) ? name[i] : '_';
		nname += toupper(c);
		}

	return nname;
	}

static void strerror_r_helper(char* result, char* buf, size_t buflen)
	{
	// Seems the GNU flavor of strerror_r may return a pointer to a static
	// string. So try to copy as much as possible into desired buffer.
	auto len = strlen(result);
	strncpy(buf, result, buflen);

	if ( len >= buflen )
		buf[buflen - 1] = 0;
	}

static void strerror_r_helper(int result, char* buf, size_t buflen)
	{ /* XSI flavor of strerror_r, no-op. */ }

void bro_strerror_r(int bro_errno, char* buf, size_t buflen)
	{
	auto res = strerror_r(bro_errno, buf, buflen);
	// GNU vs. XSI flavors make it harder to use strerror_r.
	strerror_r_helper(res, buf, buflen);
	}
