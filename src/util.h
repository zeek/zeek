// See the file "COPYING" in the main distribution directory for copyright.

#ifndef util_h
#define util_h

#ifdef __GNUC__
    #define BRO_DEPRECATED(msg) __attribute__ ((deprecated(msg)))
#elif defined(_MSC_VER)
    #define BRO_DEPRECATED(msg) __declspec(deprecated(msg)) func
#else
	#pragma message("Warning: BRO_DEPRECATED macro not implemented")
	#define BRO_DEPRECATED(msg)
#endif

// Expose C99 functionality from inttypes.h, which would otherwise not be
// available in C++.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

#include <inttypes.h>
#include <stdint.h>

#include <string>
#include <array>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <libgen.h>

#include "zeek-config.h"
#include "siphash24.h"

#ifdef DEBUG

#include <assert.h>

#define ASSERT(x)	assert(x)
#define DEBUG_MSG(x...)	fprintf(stderr, x)
#define DEBUG_fputs	fputs

#else

#define ASSERT(x)
#define DEBUG_MSG(x...)
#define DEBUG_fputs(x...)

#endif

#ifdef USE_PERFTOOLS_DEBUG
#include <gperftools/heap-checker.h>
#include <gperftools/heap-profiler.h>
extern HeapLeakChecker* heap_checker;
#endif

#include <stdint.h>

typedef uint64_t uint64;
typedef uint32_t uint32;
typedef uint16_t uint16;
typedef uint8_t uint8;

typedef int64_t int64;
typedef int32_t int32;
typedef int16_t int16;
typedef int8_t int8;

typedef int64 bro_int_t;
typedef uint64 bro_uint_t;

// "ptr_compat_uint" and "ptr_compat_int" are (un)signed integers of
// pointer size. They can be cast safely to a pointer, e.g. in Lists,
// which represent their entities as void* pointers.
//
#if SIZEOF_VOID_P == 8
typedef uint64 ptr_compat_uint;
typedef int64 ptr_compat_int;
#define PRI_PTR_COMPAT_INT PRId64 // Format to use with printf.
#define PRI_PTR_COMPAT_UINT PRIu64
#elif SIZEOF_VOID_P == 4
typedef uint32 ptr_compat_uint;
typedef int32 ptr_compat_int;
#define PRI_PTR_COMPAT_INT PRId32
#define PRI_PTR_COMPAT_UINT PRIu32
#else
# error "Unsupported pointer size."
#endif

extern "C"
	{
	#include "modp_numtoa.h"
	}

template <class T>
void delete_each(T* t)
	{
	typedef typename T::iterator iterator;
	for ( iterator it = t->begin(); it != t->end(); ++it )
		delete *it;
	}

std::string extract_ip(const std::string& i);
std::string extract_ip_and_len(const std::string& i, int* len);

inline void bytetohex(unsigned char byte, char* hex_out)
	{
	static const char hex_chars[] = "0123456789abcdef";
	hex_out[0] = hex_chars[(byte & 0xf0) >> 4];
	hex_out[1] = hex_chars[byte & 0x0f];
	}

std::string get_unescaped_string(const std::string& str);

class ODesc;

ODesc* get_escaped_string(ODesc* d, const char* str, size_t len,
                          bool escape_all);
std::string get_escaped_string(const char* str, size_t len, bool escape_all);

inline std::string get_escaped_string(const std::string& str, bool escape_all)
	{
	return get_escaped_string(str.data(), str.length(), escape_all);
	}

std::vector<std::string>* tokenize_string(std::string input,
					  const std::string& delim,
					  std::vector<std::string>* rval = 0);

extern char* copy_string(const char* s);
extern int streq(const char* s1, const char* s2);

// Returns the character corresponding to the given escape sequence (s points
// just past the '\'), and updates s to point just beyond the last character
// of the sequence.
extern int expand_escape(const char*& s);

extern char* skip_whitespace(char* s);
extern const char* skip_whitespace(const char* s);
extern char* skip_whitespace(char* s, char* end_of_s);
extern const char* skip_whitespace(const char* s, const char* end_of_s);
extern char* skip_digits(char* s);
extern char* get_word(char*& s);
extern void get_word(int length, const char* s, int& pwlen, const char*& pw);
extern void to_upper(char* s);
extern std::string to_upper(const std::string& s);
extern int decode_hex(char ch);
extern unsigned char encode_hex(int h);
#ifndef HAVE_STRCASESTR
extern char* strcasestr(const char* s, const char* find);
#endif
extern const char* strpbrk_n(size_t len, const char* s, const char* charset);
template<class T> int atoi_n(int len, const char* s, const char** end, int base, T& result);
extern char* uitoa_n(uint64 value, char* str, int n, int base, const char* prefix=0);
int strstr_n(const int big_len, const unsigned char* big,
		const int little_len, const unsigned char* little);
extern int fputs(int len, const char* s, FILE* fp);
extern bool is_printable(const char* s, int len);

// Return a lower-cased version of the string.
extern std::string strtolower(const std::string& s);

extern const char* fmt_bytes(const char* data, int len);

// Note: returns a pointer into a shared buffer.
extern const char* fmt(const char* format, va_list args);
// Note: returns a pointer into a shared buffer.
extern const char* fmt(const char* format, ...)
	__attribute__((format (printf, 1, 2)));
extern const char* fmt_access_time(double time);

extern bool ensure_intermediate_dirs(const char* dirname);
extern bool ensure_dir(const char *dirname);

// Returns true if path exists and is a directory.
bool is_dir(const std::string& path);

// Returns true if path exists and is a file.
bool is_file(const std::string& path);

// Replaces all occurences of *o* in *s* with *n*.
extern std::string strreplace(const std::string& s, const std::string& o, const std::string& n);

// Remove all leading and trailing white space from string.
extern std::string strstrip(std::string s);

extern bool hmac_key_set;
extern uint8 shared_hmac_md5_key[16];
extern bool siphash_key_set;
extern uint8 shared_siphash_key[SIPHASH_KEYLEN];

extern void hmac_md5(size_t size, const unsigned char* bytes,
			unsigned char digest[16]);

// Initializes RNGs for bro_random() and MD5 usage.  If seed is given, then
// it is used (to provide determinism).  If load_file is given, the seeds
// (both random & MD5) are loaded from that file.  This takes precedence
// over the "seed" argument.  If write_file is given, the seeds are written
// to that file.
//
extern void init_random_seed(const char* load_file, const char* write_file);

// Retrieves the initial seed computed after the very first call to
// init_random_seed(). Repeated calls to init_random_seed() will not affect
// the return value of this function.
unsigned int initial_seed();

// Returns true if the user explicitly set a seed via init_random_seed();
extern bool have_random_seed();

// A simple linear congruence PRNG. It takes its state as argument and
// returns a new random value, which can serve as state for subsequent calls.
unsigned int bro_prng(unsigned int state);

// Replacement for the system random(), to which is normally falls back
// except when a seed has been given. In that case, the function bro_prng.
long int bro_random();

// Calls the system srandom() function with the given seed if not running
// in deterministic mode, else it updates the state of the deterministic PRNG.
void bro_srandom(unsigned int seed);

extern uint64 rand64bit();

// Each event source that may generate events gets an internally unique ID.
// This is always LOCAL for a local Bro. For remote event sources, it gets
// assigned by the RemoteSerializer.
//
// FIXME: Find a nicer place for this type definition.
// Unfortunately, it introduces circular dependencies when defined in one of
// the obvious places (like Event.h or RemoteSerializer.h)

typedef ptr_compat_uint SourceID;
#define PRI_SOURCE_ID PRI_PTR_COMPAT_UINT
static const SourceID SOURCE_LOCAL = 0;

// TODO: This is a temporary marker to flag events coming in via Broker.
// Those are remote events but we don't have any further peer informationa
// available for them (as the old communication code would have). Once we
// remove RemoteSerializer, we can turn the SourceID into a simple boolean
// indicating whether it's a local or remote event.
static const SourceID SOURCE_BROKER = 0xffffffff;

extern void pinpoint();
extern int int_list_cmp(const void* v1, const void* v2);

extern const std::string& bro_path();
extern const char* bro_magic_path();
extern const char* bro_plugin_path();
extern const char* bro_plugin_activate();
extern std::string bro_prefixes();

extern const std::array<std::string, 2> script_extensions;

bool is_package_loader(const std::string& path);

extern void add_to_bro_path(const std::string& dir);


/**
 * Wrapper class for functions like dirname(3) or basename(3) that won't
 * modify the path argument and may optionally abort execution on error.
 */
class SafePathOp {
public:

	std::string result;
	bool error;

protected:

	SafePathOp()
		: result(), error()
		{ }

	void CheckValid(const char* result, const char* path, bool error_aborts);

};

class SafeDirname : public SafePathOp {
public:

	explicit SafeDirname(const char* path, bool error_aborts = true);
	explicit SafeDirname(const std::string& path, bool error_aborts = true);

private:

	void DoFunc(const std::string& path, bool error_aborts = true);
};

class SafeBasename : public SafePathOp {
public:

	explicit SafeBasename(const char* path, bool error_aborts = true);
	explicit SafeBasename(const std::string& path, bool error_aborts = true);

private:

	void DoFunc(const std::string& path, bool error_aborts = true);
};

std::string implode_string_vector(const std::vector<std::string>& v,
                                  const std::string& delim = "\n");

/**
 * Flatten a script name by replacing '/' path separators with '.'.
 * @param file A path to a Bro script.  If it is a __load__.zeek, that part
 *             is discarded when constructing the flattened the name.
 * @param prefix A string to prepend to the flattened script name.
 * @return The flattened script name.
 */
std::string flatten_script_name(const std::string& name,
                                const std::string& prefix = "");

/**
 * Return a canonical/shortened path string by removing superfluous elements
 * (path delimiters, dots referring to CWD or parent dir).
 * @param path A filesystem path.
 * @return A canonical/shortened version of \a path.
 */
std::string normalize_path(const std::string& path);

/**
 * Strip the BROPATH component from a path.
 * @param path A file/directory path that may be within a BROPATH component.
 * @return *path* minus the common BROPATH component (if any) removed.
 */
std::string without_bropath_component(const std::string& path);

/**
 * Locate a file within a given search path.
 * @param filename Name of a file to find.
 * @param path_set Colon-delimited set of paths to search for the file.
 * @param opt_ext A filename extension/suffix to allow.
 * @return Path to the found file, or an empty string if not found.
 */
std::string find_file(const std::string& filename, const std::string& path_set,
                      const std::string& opt_ext = "");

/**
 * Locate a script file within a given search path.
 * @param filename Name of a file to find.
 * @param path_set Colon-delimited set of paths to search for the file.
 * @return Path to the found file, or an empty string if not found.
 */
std::string find_script_file(const std::string& filename, const std::string& path_set);

// Wrapper around fopen(3).  Emits an error when failing to open.
FILE* open_file(const std::string& path, const std::string& mode = "r");

/** Opens a Bro script package.
 * @param path Location of a Bro script package (a directory).  Will be changed
 *             to the path of the package's loader script.
 * @param mode An fopen(3) mode.
 * @return The return value of fopen(3) on the loader script or null if one
 *         doesn't exist.
 */
FILE* open_package(std::string& path, const std::string& mode = "r");

// Renames the given file to a new temporary name, and opens a new file with
// the original name. Returns new file or NULL on error. Inits rotate_info if
// given (open time is set network time).
class RecordVal;
extern FILE* rotate_file(const char* name, RecordVal* rotate_info);

// This mimics the script-level function with the same name.
const char* log_file_name(const char* tag);

// Parse a time string of the form "HH:MM" (as used for the rotation base
// time) into a double representing the number of seconds. Returns -1 if the
// string cannot be parsed. The function's result is intended to be used with
// calc_next_rotate().
//
// This function is not thread-safe.
double parse_rotate_base_time(const char* rotate_base_time);

// Calculate the duration until the next time a file is to be rotated, based
// on the given rotate_interval and rotate_base_time. 'current' the the
// current time to be used as base, 'rotate_interval' the rotation interval,
// and 'base' the value returned by parse_rotate_base_time(). For the latter,
// if the function returned -1, that's fine, calc_next_rotate() handles that.
//
// This function is thread-safe.
double calc_next_rotate(double current, double rotate_interval, double base);

// Terminates processing gracefully, similar to pressing CTRL-C.
void terminate_processing();

// Sets the current status of the Bro process to the given string.
// If the option --status-file has been set, this is written into
// the the corresponding file.  Otherwise, the function is a no-op.
#define set_processing_status(status, location) \
	_set_processing_status(status " [" location "]\n");
void _set_processing_status(const char* status);

// Current timestamp, from a networking perspective, not a wall-clock
// perspective.  In particular, if we're reading from a savefile this
// is the time of the most recent packet, not the time returned by
// gettimeofday().
extern double network_time;

// Returns the current time.
// (In pseudo-realtime mode this is faked to be the start time of the
// trace plus the time interval Bro has been running. To avoid this,
// call with real=true).
extern double current_time(bool real=false);

// Convert a time represented as a double to a timeval struct.
extern struct timeval double_to_timeval(double t);

// Return > 0 if tv_a > tv_b, 0 if equal, < 0 if tv_a < tv_b.
extern int time_compare(struct timeval* tv_a, struct timeval* tv_b);

// Returns an integer that's very likely to be unique, even across Bro
// instances. The integer can be drawn from different pools, which is helpful
// when the randon number generator is seeded to be deterministic. In that
// case, the same sequence of integers is generated per pool.
#define UID_POOL_DEFAULT_INTERNAL 1
#define UID_POOL_DEFAULT_SCRIPT   2
#define UID_POOL_CUSTOM_SCRIPT    10 // First available custom script level pool.
extern uint64 calculate_unique_id();
extern uint64 calculate_unique_id(const size_t pool);

// For now, don't use hash_maps - they're not fully portable.
#if 0
// Use for hash_map's string keys.
struct eqstr {
	bool operator()(const char* s1, const char* s2) const
		{
		return strcmp(s1, s2) == 0;
		}
};
#endif

// Use for map's string keys.
struct ltstr {
	bool operator()(const char* s1, const char* s2) const
	{
	return strcmp(s1, s2) < 0;
	}
};

// Versions of realloc/malloc which abort() on out of memory

inline size_t pad_size(size_t size)
	{
	// We emulate glibc here (values measured on Linux i386).
	// FIXME: We should better copy the portable value definitions from glibc.
	if ( size == 0 )
		return 0;	// glibc allocated 16 bytes anyway.

	const int pad = 8;
	if ( size < 12 )
		return 2 * pad;

	return ((size+3) / pad + 1) * pad;
	}

#define padded_sizeof(x) (pad_size(sizeof(x)))

// Like write() but handles interrupted system calls by restarting. Returns
// true if the write was successful, otherwise sets errno. This function is
// thread-safe as long as no two threads write to the same descriptor.
extern bool safe_write(int fd, const char* data, int len);

// Same as safe_write(), but for pwrite().
extern bool safe_pwrite(int fd, const unsigned char* data, size_t len,
                        size_t offset);

// Wraps close(2) to emit error messages and abort on unrecoverable errors.
extern void safe_close(int fd);

extern "C" void out_of_memory(const char* where);

inline void* safe_realloc(void* ptr, size_t size)
	{
	ptr = realloc(ptr, size);
	if ( size && ! ptr )
		out_of_memory("realloc");

	return ptr;
	}

inline void* safe_malloc(size_t size)
	{
	void* ptr = malloc(size);
	if ( ! ptr )
		out_of_memory("malloc");

	return ptr;
	}

inline char* safe_strncpy(char* dest, const char* src, size_t n)
	{
	char* result = strncpy(dest, src, n);
	dest[n-1] = '\0';
	return result;
	}

inline int safe_snprintf(char* str, size_t size, const char* format, ...)
	{
	va_list al;
	va_start(al, format);
	int result = vsnprintf(str, size, format, al);
	va_end(al);
	str[size-1] = '\0';

	return result;
	}

inline int safe_vsnprintf(char* str, size_t size, const char* format, va_list al)
	{
	int result = vsnprintf(str, size, format, al);
	str[size-1] = '\0';
	return result;
	}

// Returns total memory allocations and (if available) amount actually
// handed out by malloc.
extern void get_memory_usage(uint64* total, uint64* malloced);

// Class to be used as a third argument for STL maps to be able to use
// char*'s as keys. Otherwise the pointer values will be compared instead of
// the actual string values.
struct CompareString
	{
	bool operator()(char const *a, char const *b) const
		{
		return strcmp(a, b) < 0;
		}
	};

/**
 * Canonicalizes a name by converting it to uppercase letters and replacing
 * all non-alphanumeric characters with an underscore.
 * @param name The string to canonicalize.
 * @return The canonicalized version of \a name which caller may later delete[].
 */
std::string canonify_name(const std::string& name);

/**
 * Reentrant version of strerror(). Takes care of the difference between the
 * XSI-compliant and the GNU-specific version of strerror_r().
 */
void bro_strerror_r(int bro_errno, char* buf, size_t buflen);

#endif
