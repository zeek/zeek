// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"
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

#include <string>
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

#include "input.h"
#include "util.h"
#include "Obj.h"
#include "Val.h"
#include "NetVar.h"
#include "Net.h"
#include "Reporter.h"

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
 * @param str string to escape
 * @param escape_all If true, all characters are escaped. If false, only
 * characters are escaped that are either whitespace or not printable in
 * ASCII.
 * @return A std::string containing a list of escaped hex values of the form
 * \x## */
std::string get_escaped_string(const std::string& str, bool escape_all)
	{
	char tbuf[16];
	string esc = "";

	for ( size_t i = 0; i < str.length(); ++i )
		{
		char c = str[i];

		if ( escape_all || isspace(c) || ! isascii(c) || ! isprint(c) )
			{
			snprintf(tbuf, sizeof(tbuf), "\\x%02x", str[i]);
			esc += tbuf;
			}
		else
			esc += c;
		}

	return esc;
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
			reporter->InternalError("confusion reformatting in fmt()");
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

bool is_dir(const char* path)
	{
	struct stat st;
	if ( stat(path, &st) < 0 )
		{
		if ( errno != ENOENT )
			reporter->Warning("can't stat %s: %s", path, strerror(errno));

		return false;
		}

	return S_ISDIR(st.st_mode);
	}

int hmac_key_set = 0;
uint8 shared_hmac_md5_key[16];

void hmac_md5(size_t size, const unsigned char* bytes, unsigned char digest[16])
	{
	if ( ! hmac_key_set )
		reporter->InternalError("HMAC-MD5 invoked before the HMAC key is set");

	MD5(bytes, size, digest);

	for ( int i = 0; i < 16; ++i )
		digest[i] ^= shared_hmac_md5_key[i];

	MD5(digest, 16, digest);
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

void init_random_seed(uint32 seed, const char* read_file, const char* write_file)
	{
	static const int bufsiz = 16;
	uint32 buf[bufsiz];
	memset(buf, 0, sizeof(buf));
	int pos = 0;	// accumulates entropy
	bool seeds_done = false;

	if ( read_file )
		{
		if ( ! read_random_seeds(read_file, &seed, buf, bufsiz) )
			reporter->Error("Could not load seeds from file '%s'.\n",
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
			safe_close(fd);

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
		MD5((const u_char*) buf, sizeof(buf), shared_hmac_md5_key);
		hmac_key_set = 1;
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

const char* bro_path()
	{
	const char* path = getenv("BROPATH");
	if ( ! path )
		path = ".:"
			BRO_SCRIPT_INSTALL_PATH ":"
			BRO_SCRIPT_INSTALL_PATH "/policy" ":"
			BRO_SCRIPT_INSTALL_PATH "/site";

	return path;
	}

const char* bro_magic_path()
	{
	const char* path = getenv("BROMAGIC");

	if ( ! path )
		path = BRO_MAGIC_INSTALL_PATH;

	return path;
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

const char* PACKAGE_LOADER = "__load__.bro";

// If filename is pointing to a directory that contains a file called
// PACKAGE_LOADER, returns the files path. Otherwise returns filename itself.
// In both cases, the returned string is newly allocated.
static const char* check_for_dir(const char* filename, bool load_pkgs)
	{
	if ( load_pkgs && is_dir(filename) )
		{
		char init_filename_buf[1024];
		safe_snprintf(init_filename_buf, sizeof(init_filename_buf),
			      "%s/%s", filename, PACKAGE_LOADER);

		if ( access(init_filename_buf, R_OK) == 0 )
			return copy_string(init_filename_buf);
		}

	return copy_string(filename);
	}

static FILE* open_file(const char* filename, const char** full_filename, bool load_pkgs)
	{
	filename = check_for_dir(filename, load_pkgs);

	if ( full_filename )
		*full_filename = copy_string(filename);

	FILE* f = fopen(filename, "r");

	if ( ! f )
		{
		char buf[256];
		strerror_r(errno, buf, sizeof(buf));
		reporter->Error("Failed to open file %s: %s", filename, buf);
		}

	delete [] filename;

	return f;
	}

// Canonicalizes a given 'file' that lives in 'path' into a flattened,
// dotted format.  If the optional 'prefix' argument is given, it is
// prepended to the dotted-format, separated by another dot.
// If 'file' is __load__.bro, that part is discarded when constructing
// the final dotted-format.
string dot_canon(string path, string file, string prefix)
	{
	string dottedform(prefix);
	if ( prefix != "" )
		dottedform.append(".");
	dottedform.append(path);
	char* tmp = copy_string(file.c_str());
	char* bname = basename(tmp);
	if ( ! streq(bname, PACKAGE_LOADER) )
		{
		if ( path != "" )
			dottedform.append(".");
		dottedform.append(bname);
		}
	delete [] tmp;
	size_t n;
	while ( (n = dottedform.find("/")) != string::npos )
		dottedform.replace(n, 1, ".");
	return dottedform;
	}

// returns a normalized version of a path, removing duplicate slashes,
// extraneous dots that refer to the current directory, and pops as many
// parent directories referred to by "../" as possible
const char* normalize_path(const char* path)
	{
	size_t n;
	string p(path);
	vector<string> components, final_components;
	string new_path;

	if ( p[0] == '/' )
		new_path = "/";

	while ( (n = p.find("/")) != string::npos )
		{
		components.push_back(p.substr(0, n));
		p.erase(0, n + 1);
		}
	components.push_back(p);

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

	return copy_string(new_path.c_str());
	}

// Returns the subpath of the root Bro script install/source/build directory in
// which the loaded file is located.  If it's not under a subpath of that
// directory (e.g. cwd or custom path) then the full path is returned.
void get_script_subpath(const std::string& full_filename, const char** subpath)
	{
	size_t p;
	std::string my_subpath(full_filename);

	// get the parent directory of file (if not already a directory)
	if ( ! is_dir(full_filename.c_str()) )
		{
		char* tmp = copy_string(full_filename.c_str());
		my_subpath = dirname(tmp);
		delete [] tmp;
		}

	// first check if this is some subpath of the installed scripts root path,
	// if not check if it's a subpath of the script source root path,
	// then check if it's a subpath of the build directory (where BIF scripts
	// will get generated).
	// If none of those, will just use the given directory.
	if ( (p = my_subpath.find(BRO_SCRIPT_INSTALL_PATH)) != std::string::npos )
		my_subpath.erase(0, strlen(BRO_SCRIPT_INSTALL_PATH));
	else if ( (p = my_subpath.find(BRO_SCRIPT_SOURCE_PATH)) != std::string::npos )
		my_subpath.erase(0, strlen(BRO_SCRIPT_SOURCE_PATH));
	else if ( (p = my_subpath.find(BRO_BUILD_SOURCE_PATH)) != std::string::npos )
		my_subpath.erase(0, strlen(BRO_BUILD_SOURCE_PATH));
	else if ( (p = my_subpath.find(BRO_BUILD_SCRIPTS_PATH)) != std::string::npos )
		my_subpath.erase(0, strlen(BRO_BUILD_SCRIPTS_PATH));

	// if root path found, remove path separators until next path component
	if ( p != std::string::npos )
		while ( my_subpath.size() && my_subpath[0] == '/' )
			my_subpath.erase(0, 1);

	*subpath = normalize_path(my_subpath.c_str());
	}

extern string current_scanned_file_path;

FILE* search_for_file(const char* filename, const char* ext,
			const char** full_filename, bool load_pkgs,
			const char** bropath_subpath)
	{
	// If the file is a literal absolute path we don't have to search,
	// just return the result of trying to open it.  If the file is
	// might be a relative path, check first if it's a real file that
	// can be referenced from cwd, else we'll try to search for it based
	// on what path the currently-loading script is in as well as the
	// standard BROPATH paths.
	if ( filename[0] == '/' ||
	    (filename[0] == '.' && access(filename, R_OK) == 0) )
		{
		if ( bropath_subpath )
			{
			char* tmp = copy_string(filename);
			*bropath_subpath = copy_string(dirname(tmp));
			delete [] tmp;
			}
		return open_file(filename, full_filename, load_pkgs);
		}

	char path[1024], full_filename_buf[1024];

	// Prepend the currently loading script's path to BROPATH so that
	// @loads can be referenced relatively.
	if ( current_scanned_file_path != "" && filename[0] == '.' )
		safe_snprintf(path, sizeof(path), "%s:%s",
		              current_scanned_file_path.c_str(), bro_path());
	else
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
			{
			if ( bropath_subpath )
				get_script_subpath(full_filename_buf, bropath_subpath);
			return open_file(full_filename_buf, full_filename, load_pkgs);
			}

		safe_snprintf(full_filename_buf, sizeof(full_filename_buf),
				"%s/%s", dir_beginning, filename);
		if ( access(full_filename_buf, R_OK) == 0 )
			{
			if ( bropath_subpath )
				get_script_subpath(full_filename_buf, bropath_subpath);
			return open_file(full_filename_buf, full_filename, load_pkgs);
			}

		dir_beginning = ++dir_ending;
		}

	if ( full_filename )
		*full_filename = copy_string(filename);
	if ( bropath_subpath )
			{
			char* tmp = copy_string(filename);
			*bropath_subpath = copy_string(dirname(tmp));
			delete [] tmp;
			}

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
	// Calculate start of day.
	time_t teatime = time_t(current);

	struct tm t;
	t = *localtime_r(&teatime, &t);
	t.tm_hour = t.tm_min = t.tm_sec = 0;
	double startofday = mktime(&t);

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

	if ( fd < 0 )
		{
		char buf[256];
		strerror_r(errno, buf, sizeof(buf));
		reporter->Error("Failed to open process status file '%s': %s",
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
		strerror_r(errno, buf, sizeof(buf));
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

// Being selective of which components of MAGIC_NO_CHECK_BUILTIN are actually
// known to be problematic, but keeping rest of libmagic's builtin checks.
#define DISABLE_LIBMAGIC_BUILTIN_CHECKS  ( \
/*  MAGIC_NO_CHECK_COMPRESS | */ \
/*  MAGIC_NO_CHECK_TAR  | */ \
/*  MAGIC_NO_CHECK_SOFT | */ \
/*  MAGIC_NO_CHECK_APPTYPE  | */ \
/*  MAGIC_NO_CHECK_ELF  | */ \
/*  MAGIC_NO_CHECK_TEXT | */ \
    MAGIC_NO_CHECK_CDF  | \
    MAGIC_NO_CHECK_TOKENS  \
/*  MAGIC_NO_CHECK_ENCODING */ \
)

void bro_init_magic(magic_t* cookie_ptr, int flags)
	{
	if ( ! cookie_ptr || *cookie_ptr )
		return;

	*cookie_ptr = magic_open(flags|DISABLE_LIBMAGIC_BUILTIN_CHECKS);

	// Use our custom database for mime types, but the default database
	// from libmagic for the verbose file type.
	const char* database = (flags & MAGIC_MIME) ? bro_magic_path() : 0;

	if ( ! *cookie_ptr )
		{
		const char* err = magic_error(*cookie_ptr);
		if ( ! err )
			err = "unknown";

		reporter->InternalError("can't init libmagic: %s", err);
		}

	else if ( magic_load(*cookie_ptr, database) < 0 )
		{
		const char* err = magic_error(*cookie_ptr);
		if ( ! err )
			err = "unknown";

		const char* db_name = database ? database : "<default>";
		reporter->InternalError("can't load magic file %s: %s", db_name, err);
		magic_close(*cookie_ptr);
		*cookie_ptr = 0;
		}
	}

const char* bro_magic_buffer(magic_t cookie, const void* buffer, size_t length)
	{
	const char* rval = magic_buffer(cookie, buffer, length);
	if ( ! rval )
		{
		const char* err = magic_error(cookie);
		reporter->Error("magic_buffer error: %s", err ? err : "unknown");
		}

	return rval;
	}

const char* canonify_name(const char* name)
	{
	unsigned int len = strlen(name);
	char* nname = new char[len + 1];

	for ( unsigned int i = 0; i < len; i++ )
		{
		char c = isalnum(name[i]) ? name[i] : '_';
		nname[i] = toupper(c);
		}

	nname[len] = '\0';
	return nname;
	}
