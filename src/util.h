// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// Expose C99 functionality from inttypes.h, which would otherwise not be
// available in C++.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

#include <cinttypes>
#include <cstdint>

#include <string>
#include <string_view>
#include <array>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <libgen.h>
#include <memory> // std::unique_ptr

#include "zeek-config.h"

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
#include <pthread.h>

#ifdef HAVE_LINUX
#include <sys/prctl.h>
#endif

#ifdef __FreeBSD__
#include <pthread_np.h>
#endif

[[deprecated("Remove in v4.1. Use uint64_t instead.")]]
typedef uint64_t uint64;
[[deprecated("Remove in v4.1. Use uint32_t instead.")]]
typedef uint32_t uint32;
[[deprecated("Remove in v4.1. Use uint16_t instead.")]]
typedef uint16_t uint16;
[[deprecated("Remove in v4.1. Use uint8_t instead.")]]
typedef uint8_t uint8;

[[deprecated("Remove in v4.1. Use int64_t instead.")]]
typedef int64_t int64;
[[deprecated("Remove in v4.1. Use int32_t instead.")]]
typedef int32_t int32;
[[deprecated("Remove in v4.1. Use int16_t instead.")]]
typedef int16_t int16;
[[deprecated("Remove in v4.1. Use int8_t instead.")]]
typedef int8_t int8;

// "ptr_compat_uint" and "ptr_compat_int" are (un)signed integers of
// pointer size. They can be cast safely to a pointer, e.g. in Lists,
// which represent their entities as void* pointers.
//
#define PRI_PTR_COMPAT_INT PRIdPTR // Format to use with printf.
#define PRI_PTR_COMPAT_UINT PRIuPTR
#if SIZEOF_VOID_P == 8
typedef uint64_t ptr_compat_uint [[deprecated("Remove in v4.1. Use std::uintptr_t.")]];
typedef int64_t ptr_compat_int [[deprecated("Remove in v4.1. Use std::intptr_t.")]];
#elif SIZEOF_VOID_P == 4
typedef uint32_t ptr_compat_uint [[deprecated("Remove in v4.1. Use std::uintptr_t")]];
typedef int32_t ptr_compat_int [[deprecated("Remove in v4.1. Use std::iintptr_t")]];
#else
# error "Unsupported pointer size."
#endif

extern "C"
	{
	#include "modp_numtoa.h"
	}

using bro_int_t = int64_t;
using bro_uint_t = uint64_t;

ZEEK_FORWARD_DECLARE_NAMESPACED(ODesc, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(RecordVal, zeek);

#ifndef HAVE_STRCASESTR
extern char* strcasestr(const char* s, const char* find);
#endif

// Current timestamp, from a networking perspective, not a wall-clock
// perspective.  In particular, if we're reading from a savefile this
// is the time of the most recent packet, not the time returned by
// gettimeofday().
extern double& network_time [[deprecated("Remove in v4.1. Use zeek::net::network_time.")]];

[[deprecated("Remove in v4.1: Use system snprintf instead")]]
inline int safe_snprintf(char* str, size_t size, const char* format, ...)
	{
	va_list al;
	va_start(al, format);
	int result = vsnprintf(str, size, format, al);
	va_end(al);
	str[size-1] = '\0';

	return result;
	}

[[deprecated("Remove in v4.1: Use system vsnprintf instead")]]
inline int safe_vsnprintf(char* str, size_t size, const char* format, va_list al)
	{
	int result = vsnprintf(str, size, format, al);
	str[size-1] = '\0';
	return result;
	}

// This is used by the patricia code and so it remains outside of hte namespace.
extern "C" void out_of_memory(const char* where);

namespace zeek::util {

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
	static constexpr char hex_chars[] = "0123456789abcdef";
	hex_out[0] = hex_chars[(byte & 0xf0) >> 4];
	hex_out[1] = hex_chars[byte & 0x0f];
	}

std::string get_unescaped_string(const std::string& str);

zeek::ODesc* get_escaped_string(zeek::ODesc* d, const char* str, size_t len,
                                bool escape_all);
std::string get_escaped_string(const char* str, size_t len, bool escape_all);

inline std::string get_escaped_string(const std::string& str, bool escape_all)
	{
	return get_escaped_string(str.data(), str.length(), escape_all);
	}

std::vector<std::string>* tokenize_string(std::string_view input,
					  std::string_view delim,
					  std::vector<std::string>* rval = nullptr, int limit = 0);

std::vector<std::string_view> tokenize_string(std::string_view input, const char delim) noexcept;

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
extern const char* strpbrk_n(size_t len, const char* s, const char* charset);
template<class T> int atoi_n(int len, const char* s, const char** end, int base, T& result);
extern char* uitoa_n(uint64_t value, char* str, int n, int base, const char* prefix=nullptr);
int strstr_n(const int big_len, const unsigned char* big,
		const int little_len, const unsigned char* little);
extern int fputs(int len, const char* s, FILE* fp);
extern bool is_printable(const char* s, int len);

// Return a lower-cased version of the string.
extern std::string strtolower(const std::string& s);

extern const char* fmt_bytes(const char* data, int len);

// Note: returns a pointer into a shared buffer.
extern const char* vfmt(const char* format, va_list args);
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

extern void hmac_md5(size_t size, const unsigned char* bytes,
                     unsigned char digest[16]);

// Initializes RNGs for zeek::random_number() and MD5 usage.  If load_file is given,
// the seeds (both random & MD5) are loaded from that file.  This takes
// precedence over the "use_empty_seeds" argument, which just
// zero-initializes all seed values.  If write_file is given, the seeds are
// written to that file.
extern void init_random_seed(const char* load_file, const char* write_file,
                             bool use_empty_seeds);

// Retrieves the initial seed computed after the very first call to
// init_random_seed(). Repeated calls to init_random_seed() will not affect
// the return value of this function.
unsigned int initial_seed();

// Returns true if the user explicitly set a seed via init_random_seed();
extern bool have_random_seed();

extern uint64_t rand64bit();

// Each event source that may generate events gets an internally unique ID.
// This is always LOCAL for a local Bro. For remote event sources, it gets
// assigned by the RemoteSerializer.
//
// FIXME: Find a nicer place for this type definition.
// Unfortunately, it introduces circular dependencies when defined in one of
// the obvious places (like Event.h or RemoteSerializer.h)

using SourceID = std::uintptr_t;
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

extern const std::string& zeek_path();
extern const char* zeek_magic_path();
extern const char* zeek_plugin_path();
extern const char* zeek_plugin_activate();
extern std::string zeek_prefixes();

extern const std::array<std::string, 2> script_extensions;

/** Prints a warning if the filename ends in .bro. */
void warn_if_legacy_script(std::string_view filename);

bool is_package_loader(const std::string& path);

extern void add_to_zeek_path(const std::string& dir);


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
 * @param file A path to a Zeek script.  If it is a __load__.zeek, that part
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
std::string normalize_path(std::string_view path);

/**
 * Strip the ZEEKPATH component from a path.
 * @param path A file/directory path that may be within a ZEEKPATH component.
 * @return *path* minus the common ZEEKPATH component (if any) removed.
 */
std::string without_zeekpath_component(std::string_view path);

/**
 * Gets the full path used to invoke some executable.
 * @param invocation  any possible string that may be seen in argv[0], such as
 *                    absolute path, relative path, or name to lookup in PATH.
 * @return the absolute path to the executable file
 */
std::string get_exe_path(const std::string& invocation);

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

/** Opens a Zeek script package.
 * @param path Location of a Zeek script package (a directory).  Will be changed
 *             to the path of the package's loader script.
 * @param mode An fopen(3) mode.
 * @return The return value of fopen(3) on the loader script or null if one
 *         doesn't exist.
 */
FILE* open_package(std::string& path, const std::string& mode = "r");

// Renames the given file to a new temporary name, and opens a new file with
// the original name. Returns new file or NULL on error. Inits rotate_info if
// given (open time is set network time).
extern FILE* rotate_file(const char* name, zeek::RecordVal* rotate_info);

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

// Sets the current status of the Zeek process to the given string.
// If the option --status-file has been set, this is written into
// the the corresponding file.  Otherwise, the function is a no-op.
void set_processing_status(const char* status, const char* reason);

// Returns the current time.
// (In pseudo-realtime mode this is faked to be the start time of the
// trace plus the time interval Zeek has been running. To avoid this,
// call with real=true).
extern double current_time(bool real=false);

// Convert a time represented as a double to a timeval struct.
extern struct timeval double_to_timeval(double t);

// Return > 0 if tv_a > tv_b, 0 if equal, < 0 if tv_a < tv_b.
extern int time_compare(struct timeval* tv_a, struct timeval* tv_b);

// Returns an integer that's very likely to be unique, even across Zeek
// instances. The integer can be drawn from different pools, which is helpful
// when the random number generator is seeded to be deterministic. In that
// case, the same sequence of integers is generated per pool.
#define UID_POOL_DEFAULT_INTERNAL 1
#define UID_POOL_DEFAULT_SCRIPT   2
#define UID_POOL_CUSTOM_SCRIPT    10 // First available custom script level pool.
extern uint64_t calculate_unique_id();
extern uint64_t calculate_unique_id(const size_t pool);

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

#define padded_sizeof(x) (zeek::util::pad_size(sizeof(x)))

// Like write() but handles interrupted system calls by restarting. Returns
// true if the write was successful, otherwise sets errno. This function is
// thread-safe as long as no two threads write to the same descriptor.
extern bool safe_write(int fd, const char* data, int len);

// Same as safe_write(), but for pwrite().
extern bool safe_pwrite(int fd, const unsigned char* data, size_t len,
                        size_t offset);

// Wraps close(2) to emit error messages and abort on unrecoverable errors.
extern void safe_close(int fd);

// Versions of realloc/malloc which abort() on out of memory

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
	char* result = strncpy(dest, src, n-1);
	dest[n-1] = '\0';
	return result;
	}

// Returns total memory allocations and (if available) amount actually
// handed out by malloc.
extern void get_memory_usage(uint64_t* total, uint64_t* malloced);

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
void zeek_strerror_r(int zeek_errno, char* buf, size_t buflen);

/**
 * A wrapper function for getenv().  Helps check for existence of
 * legacy environment variable names that map to the latest \a name.
 */
char* zeekenv(const char* name);

/**
 * Escapes bytes in a string that are not valid UTF8 characters with \xYY format. Used
 * by the JSON writer and BIF methods.
 * @param val the input string to be escaped
 * @return the escaped string
 */
std::string json_escape_utf8(const std::string& val);

/**
 * Set the process/thread name.  May not be supported on all OSs.
 * @param name  new name for the process/thread.  OS limitations typically
 * truncate the name to 15 bytes maximum.
 * @param tid  handle of thread whose name shall change
 */
void set_thread_name(const char* name, pthread_t tid = pthread_self());

/**
 * A platform-independent PRNG implementation.  Note that this is not
 * necessarily a "statistically sound" implementation as the main purpose is
 * not for production use, but rather for regression testing.
 * @param state  The value used to generate the next random number.
 * @return  A new random value generated from *state* and that can passed
 * back into subsequent calls to generate further random numbers.
 */
long int prng(long int state);

/**
 * Wrapper for system random() in the default case, but when running in
 * deterministic mode, uses the platform-independent zeek::prng()
 * to obtain consistent results since implementations of rand() may vary.
 * @return  A value in the range [0, zeek::max_random()].
 */
long int random_number();

/**
 * @return The maximum value that can be returned from zeek::random_number().
 * When not using deterministic-mode, this is always equivalent to RAND_MAX.
 */
long int max_random();

/**
 * Wrapper for system srandom() in the default case, but when running in
 * deterministic mode, updates the state used for calling zeek::prng()
 * inside of zeek::random_number().
 * @param seed  Value to use for initializing the PRNG.
 */
void seed_random(unsigned int seed);

} // namespace zeek::util

// A simple linear congruence PRNG. It takes its state as argument and
// returns a new random value, which can serve as state for subsequent calls.
[[deprecated("Remove in v4.1.  Use zeek::util::prng()")]]
unsigned int bro_prng(unsigned int state);

// Replacement for the system random(), to which is normally falls back
// except when a seed has been given. In that case, the function bro_prng.
[[deprecated("Remove in v4.1.  Use zeek::util::random_number()")]]
long int bro_random();

// Calls the system srandom() function with the given seed if not running
// in deterministic mode, else it updates the state of the deterministic PRNG.
[[deprecated("Remove in v4.1.  Use zeek::util::seed_random()")]]
void bro_srandom(unsigned int seed);

template<class T>
[[ deprecated("Remove in v4.1. Use zeek::util::delete_each.")]]
void delete_each(T* t) { zeek::util::delete_each<T>(t); }

constexpr auto extract_ip [[deprecated("Remove in v4.1. Use zeek::util::extract_ip.")]] = zeek::util::extract_ip;
constexpr auto extract_ip_and_len [[deprecated("Remove in v4.1. Use zeek::util::extract_ip_and_len.")]] = zeek::util::extract_ip_and_len;
constexpr auto bytetohex [[deprecated("Remove in v4.1. Use zeek::util::bytetohex.")]] = zeek::util::bytetohex;
constexpr auto get_unescaped_string [[deprecated("Remove in v4.1. Use zeek::util::get_unescaped_string.")]] = zeek::util::get_unescaped_string;

[[deprecated("Remove in v4.1. Use zeek::util::get_escaped_string.")]]
extern zeek::ODesc* get_escaped_string(zeek::ODesc* d, const char* str, size_t len, bool escape_all);
[[deprecated("Remove in v4.1. Use zeek::util::get_escaped_string.")]]
extern std::string get_escaped_string(const char* str, size_t len, bool escape_all);
[[deprecated("Remove in v4.1. Use zeek::util::get_escaped_string.")]]
extern std::string get_escaped_string(const std::string& str, bool escape_all);
[[deprecated("Remove in v4.1. Use zeek::util::tokenize_string.")]]
extern std::vector<std::string>* tokenize_string(std::string_view input,
                                                 std::string_view delim,
                                                 std::vector<std::string>* rval = nullptr, int limit = 0);
[[deprecated("Remove in v4.1. Use zeek::util::tokenize_string.")]]
std::vector<std::string_view> tokenize_string(std::string_view input, const char delim) noexcept;

constexpr auto copy_string [[deprecated("Remove in v4.1. Use zeek::util::copy_string.")]] = zeek::util::copy_string;
constexpr auto streq [[deprecated("Remove in v4.1. Use zeek::util::streq.")]] = zeek::util::streq;
constexpr auto expand_escape [[deprecated("Remove in v4.1. Use zeek::util::expand_escape.")]] = zeek::util::expand_escape;
constexpr auto skip_digits [[deprecated("Remove in v4.1. Use zeek::util::skip_digits.")]] = zeek::util::skip_digits;

[[deprecated("Remove in v4.1. Use zeek::util::skip_whitespace.")]]
extern char* skip_whitespace(char* s);
[[deprecated("Remove in v4.1. Use zeek::util::skip_whitespace.")]]
extern const char* skip_whitespace(const char* s);
[[deprecated("Remove in v4.1. Use zeek::util::skip_whitespace.")]]
extern char* skip_whitespace(char* s, char* end_of_s);
[[deprecated("Remove in v4.1. Use zeek::util::skip_whitespace.")]]
extern const char* skip_whitespace(const char* s, const char* end_of_s);

[[deprecated("Remove in v4.1. Use zeek::util::get_word.")]]
extern char* get_word(char*& s);
[[deprecated("Remove in v4.1. Use zeek::util::get_word.")]]
extern void get_word(int length, const char* s, int& pwlen, const char*& pw);
[[deprecated("Remove in v4.1. Use zeek::util::to_upper.")]]
extern void to_upper(char* s);
[[deprecated("Remove in v4.1. Use zeek::util::to_upper.")]]
extern std::string to_upper(const std::string& s);

constexpr auto decode_hex [[deprecated("Remove in v4.1. Use zeek::util::decode_hex.")]] = zeek::util::decode_hex;
constexpr auto encode_hex [[deprecated("Remove in v4.1. Use zeek::util::encode_hex.")]] = zeek::util::encode_hex;
constexpr auto strpbrk_n [[deprecated("Remove in v4.1. Use zeek::util::strpbrk_n.")]] = zeek::util::strpbrk_n;
constexpr auto strstr_n [[deprecated("Remove in v4.1. Use zeek::util::strstr_n.")]] = zeek::util::strstr_n;

template<class T>
[[deprecated("Remove in v4.1. Use zeek::util::atoi_n.")]]
int atoi_n(int len, const char* s, const char** end, int base, T& result)
	{ return zeek::util::atoi_n<T>(len, s, end, base, result); }

[[deprecated("Remove in v4.1. Use zeek::util::uitoa_n.")]]
extern char* uitoa_n(uint64_t value, char* str, int n, int base, const char* prefix=nullptr);

[[deprecated("Remove in v4.1. Use zeek::util::fputs.")]]
extern int fputs(int len, const char* s, FILE* fp);

constexpr auto is_printable [[deprecated("Remove in v4.1. Use zeek::util::is_printable.")]] = zeek::util::is_printable;
constexpr auto strtolower [[deprecated("Remove in v4.1. Use zeek::util::strtolower.")]] = zeek::util::strtolower;
constexpr auto fmt_bytes [[deprecated("Remove in v4.1. Use zeek::util::fmt_bytes.")]] = zeek::util::fmt_bytes;
constexpr auto vfmt [[deprecated("Remove in v4.1. Use zeek::util::vfmt.")]] = zeek::util::vfmt;
constexpr auto fmt [[deprecated("Remove in v4.1. Use zeek::util::fmt.")]] = zeek::util::fmt;
constexpr auto fmt_access_time [[deprecated("Remove in v4.1. Use zeek::util::fmt_access_time.")]] = zeek::util::fmt_access_time;
constexpr auto ensure_intermediate_dirs [[deprecated("Remove in v4.1. Use zeek::util::ensure_intermediate_dirs.")]] = zeek::util::ensure_intermediate_dirs;
constexpr auto ensure_dir [[deprecated("Remove in v4.1. Use zeek::util::ensure_dir.")]] = zeek::util::ensure_dir;
constexpr auto is_dir [[deprecated("Remove in v4.1. Use zeek::util::is_dir.")]] = zeek::util::is_dir;
constexpr auto is_file [[deprecated("Remove in v4.1. Use zeek::util::is_file.")]] = zeek::util::is_file;
constexpr auto strreplace [[deprecated("Remove in v4.1. Use zeek::util::strreplace.")]] = zeek::util::strreplace;
constexpr auto strstrip [[deprecated("Remove in v4.1. Use zeek::util::strstrip.")]] = zeek::util::strstrip;
constexpr auto hmac_md5 [[deprecated("Remove in v4.1. Use zeek::util::hmac_md5.")]] = zeek::util::hmac_md5;
constexpr auto init_random_seed [[deprecated("Remove in v4.1. Use zeek::util::init_random_seed.")]] = zeek::util::init_random_seed;
constexpr auto initial_seed [[deprecated("Remove in v4.1. Use zeek::util::initial_seed.")]] = zeek::util::initial_seed;
constexpr auto have_random_seed [[deprecated("Remove in v4.1. Use zeek::util::have_random_seed.")]] = zeek::util::have_random_seed;
constexpr auto rand64bit [[deprecated("Remove in v4.1. Use zeek::util::rand64bit.")]] = zeek::util::rand64bit;

using SourceID [[deprecated("Remove in v4.1. Use zeek::util::SourceID.")]] = zeek::util::SourceID;
static const zeek::util::SourceID SOURCE_LOCAL [[deprecated("Remove in v4.1. Use zeek::util::SOURCE_LOCAL.")]] = zeek::util::SOURCE_LOCAL;
static const zeek::util::SourceID SOURCE_BROKER [[deprecated("Remove in v4.1. Use zeek::util::SOURCE_BROKER.")]] = zeek::util::SOURCE_BROKER;

constexpr auto pinpoint [[deprecated("Remove in v4.1. Use zeek::util::pinpoint.")]] = zeek::util::pinpoint;
constexpr auto int_list_cmp [[deprecated("Remove in v4.1. Use zeek::util::int_list_cmp.")]] = zeek::util::int_list_cmp;
constexpr auto bro_path [[deprecated("Remove in v4.1. Use zeek::util::zeek_path.")]] = zeek::util::zeek_path;
constexpr auto bro_magic_path [[deprecated("Remove in v4.1. Use zeek::util::zeek_magic_path.")]] = zeek::util::zeek_magic_path;
constexpr auto bro_plugin_path [[deprecated("Remove in v4.1. Use zeek::util::zeek_plugin_path.")]] = zeek::util::zeek_plugin_path;
constexpr auto bro_plugin_activate [[deprecated("Remove in v4.1. Use zeek::util::zeek_plugin_activate.")]] = zeek::util::zeek_plugin_activate;
constexpr auto bro_prefixes [[deprecated("Remove in v4.1. Use zeek::util::zeek_prefixes.")]] = zeek::util::zeek_prefixes;

extern const std::array<std::string, 2>& script_extensions [[deprecated("Remove in v4.1. Use zeek::util::script_extensions.")]];

constexpr auto warn_if_legacy_script [[deprecated("Remove in v4.1. Use zeek::util::warn_if_legacy_script.")]] = zeek::util::warn_if_legacy_script;
constexpr auto is_package_loader [[deprecated("Remove in v4.1. Use zeek::util::is_package_loader.")]] = zeek::util::is_package_loader;
constexpr auto add_to_bro_path [[deprecated("Remove in v4.1. Use zeek::util::add_to_zeek_path.")]] = zeek::util::add_to_zeek_path;

using SafePathOp [[deprecated("Remove in v4.1. Use zeek::util::SafePathOp.")]] = zeek::util::SafePathOp;
using SafeDirname [[deprecated("Remove in v4.1. Use zeek::util::SafeDirname.")]] = zeek::util::SafeDirname;
using SafeBasename [[deprecated("Remove in v4.1. Use zeek::util::SafeBasename.")]] = zeek::util::SafeBasename;

[[deprecated("Remove in v4.1. Use zeek::util::implode_string_vector.")]]
std::string implode_string_vector(const std::vector<std::string>& v,
                                  const std::string& delim = "\n");
[[deprecated("Remove in v4.1. Use zeek::util::flatten_script_name.")]]
std::string flatten_script_name(const std::string& name,
                                const std::string& prefix = "");

constexpr auto normalize_path [[deprecated("Remove in v4.1. Use zeek::util::normalize_path.")]] = zeek::util::normalize_path;
constexpr auto without_bropath_component [[deprecated("Remove in v4.1. Use zeek::util::without_zeekpath_component.")]] = zeek::util::without_zeekpath_component;
constexpr auto get_exe_path [[deprecated("Remove in v4.1. Use zeek::util::get_exe_path.")]] = zeek::util::get_exe_path;
constexpr auto find_script_file [[deprecated("Remove in v4.1. Use zeek::util::find_script_file.")]] = zeek::util::find_script_file;

[[deprecated("Remove in v4.1. Use zeek::util::find_file.")]]
std::string find_file(const std::string& filename, const std::string& path_set,
                      const std::string& opt_ext = "");
[[deprecated("Remove in v4.1. Use zeek::util::open_file.")]]
FILE* open_file(const std::string& path, const std::string& mode = "r");
[[deprecated("Remove in v4.1. Use zeek::util::open_package.")]]
FILE* open_package(std::string& path, const std::string& mode = "r");

constexpr auto rotate_file [[deprecated("Remove in v4.1. Use zeek::util::rotate_file.")]] = zeek::util::rotate_file;
constexpr auto log_file_name [[deprecated("Remove in v4.1. Use zeek::util::log_file_name.")]] = zeek::util::log_file_name;
constexpr auto parse_rotate_base_time [[deprecated("Remove in v4.1. Use zeek::util::parse_rotate_base_time.")]] = zeek::util::parse_rotate_base_time;
constexpr auto calc_next_rotate [[deprecated("Remove in v4.1. Use zeek::util::calc_next_rotate.")]] = zeek::util::calc_next_rotate;
constexpr auto terminate_processing [[deprecated("Remove in v4.1. Use zeek::util::terminate_processing.")]] = zeek::util::terminate_processing;
constexpr auto set_processing_status [[deprecated("Remove in v4.1. Use zeek::util::set_processing_status.")]] = zeek::util::set_processing_status;

[[deprecated("Remove in v4.1. Use zeek::util::current_time.")]]
extern double current_time(bool real=false);

constexpr auto double_to_timeval [[deprecated("Remove in v4.1. Use zeek::util::double_to_timeval.")]] = zeek::util::double_to_timeval;
constexpr auto time_compare [[deprecated("Remove in v4.1. Use zeek::util::time_compare.")]] = zeek::util::time_compare;

[[deprecated("Remove in v4.1. Use zeek::util::calculate_unique_id.")]]
extern uint64_t calculate_unique_id();
[[deprecated("Remove in v4.1. Use zeek::util::calculate_unique_id.")]]
extern uint64_t calculate_unique_id(const size_t pool);

using ltstr [[deprecated("Remove in v4.1. Use zeek::util::ltstr.")]] = zeek::util::ltstr;
constexpr auto pad_size [[deprecated("Remove in v4.1. Use zeek::util::pad_size.")]] = zeek::util::pad_size;
constexpr auto safe_write [[deprecated("Remove in v4.1. Use zeek::util::safe_write.")]] = zeek::util::safe_write;
constexpr auto safe_pwrite [[deprecated("Remove in v4.1. Use zeek::util::safe_pwrite.")]] = zeek::util::safe_pwrite;
constexpr auto safe_close [[deprecated("Remove in v4.1. Use zeek::util::safe_close.")]] = zeek::util::safe_close;
constexpr auto safe_realloc [[deprecated("Remove in v4.1. Use zeek::util::safe_realloc.")]] = zeek::util::safe_realloc;
constexpr auto safe_malloc [[deprecated("Remove in v4.1. Use zeek::util::safe_malloc.")]] = zeek::util::safe_malloc;
constexpr auto safe_strncpy [[deprecated("Remove in v4.1. Use zeek::util::safe_strncpy.")]] = zeek::util::safe_strncpy;
constexpr auto get_memory_usage [[deprecated("Remove in v4.1. Use zeek::util::get_memory_usage.")]] = zeek::util::get_memory_usage;
using CompareString [[deprecated("Remove in v4.1. Use zeek::util::CompareString.")]] = zeek::util::CompareString;
constexpr auto canonify_name [[deprecated("Remove in v4.1. Use zeek::util::canonify_name.")]] = zeek::util::canonify_name;
constexpr auto bro_strerror_r [[deprecated("Remove in v4.1. Use zeek::util::zeek_strerror_r.")]] = zeek::util::zeek_strerror_r;
constexpr auto zeekenv [[deprecated("Remove in v4.1. Use zeek::util::zeekenv.")]] = zeek::util::zeekenv;
constexpr auto json_escape_utf8 [[deprecated("Remove in v4.1. Use zeek::util::json_escape_utf8.")]] = zeek::util::json_escape_utf8;

namespace zeek {
	[[deprecated("Remove in v4.1. Use zeek::util::set_thread_name.")]]
	void set_thread_name(const char* name, pthread_t tid = pthread_self());

	constexpr auto prng [[deprecated("Remove in v4.1. Use zeek::util::prng.")]] = zeek::util::prng;
	constexpr auto random_number [[deprecated("Remove in v4.1. Use zeek::util::random_number.")]] = zeek::util::random_number;
	constexpr auto max_random [[deprecated("Remove in v4.1. Use zeek::util::max_random.")]] = zeek::util::max_random;
	constexpr auto seed_random [[deprecated("Remove in v4.1. Use zeek::util::seed_random.")]] = zeek::util::seed_random;
}
