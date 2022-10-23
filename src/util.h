// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"

// Expose C99 functionality from inttypes.h, which would otherwise not be
// available in C++.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

#include <libgen.h>
#include <array>
#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory> // std::unique_ptr
#include <string>
#include <string_view>
#include <vector>

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

#ifdef DEBUG

#include <cassert>

#define ASSERT(x) assert(x)
#define DEBUG_MSG(x...) fprintf(stderr, x)
#define DEBUG_fputs fputs

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

#include <pthread.h>

#ifdef HAVE_LINUX
#include <sys/prctl.h>
#endif

#ifdef __FreeBSD__
#include <pthread_np.h>
#endif

extern "C"
	{
#include "zeek/3rdparty/modp_numtoa.h"
	}

#include "zeek/3rdparty/ghc/filesystem.hpp"

using zeek_int_t = int64_t;
using zeek_uint_t = uint64_t;
using bro_int_t [[deprecated("Remove in v6.1. Use zeek_int_t.")]] = zeek_int_t;
using bro_uint_t [[deprecated("Remove in v6.1. Use zeek_uint_t.")]] = zeek_uint_t;

#ifndef HAVE_STRCASESTR
extern char* strcasestr(const char* s, const char* find);
#endif

// This is used by the patricia code and so it remains outside of the namespace.
extern "C" void out_of_memory(const char* where);

namespace zeek
	{

class ODesc;
class RecordVal;

// Expose ghc::filesystem as zeek::filesystem until we can
// switch to std::filesystem.
namespace filesystem = ghc::filesystem;

namespace util
	{
namespace detail
	{

std::string extract_ip(const std::string& i);
std::string extract_ip_and_len(const std::string& i, int* len);

// Returns the character corresponding to the given escape sequence (s points
// just past the '\'), and updates s to point just beyond the last character
// of the sequence.
extern int expand_escape(const char*& s);

extern const char* fmt_access_time(double time);

extern bool ensure_intermediate_dirs(const char* dirname);
extern bool ensure_dir(const char* dirname);

extern void hmac_md5(size_t size, const unsigned char* bytes, unsigned char digest[16]);

// Initializes RNGs for zeek::random_number() and MD5 usage.  If load_file is given,
// the seeds (both random & MD5) are loaded from that file.  This takes
// precedence over the "use_empty_seeds" argument, which just
// zero-initializes all seed values.  If write_file is given, the seeds are
// written to that file.
extern void init_random_seed(const char* load_file, const char* write_file, bool use_empty_seeds);

// Retrieves the initial seed computed after the very first call to
// init_random_seed(). Repeated calls to init_random_seed() will not affect
// the return value of this function.
unsigned int initial_seed();

// Returns true if the user explicitly set a seed via init_random_seed();
extern bool have_random_seed();

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

/**
 * Set the process/thread name.  May not be supported on all OSs.
 * @param name  new name for the process/thread.  OS limitations typically
 * truncate the name to 15 bytes maximum.
 * @param tid  handle of thread whose name shall change
 */
void set_thread_name(const char* name, pthread_t tid = pthread_self());

// Each event source that may generate events gets an internally unique ID.
// This is always LOCAL for a local Zeek. For remote event sources, it gets
// assigned by the RemoteSerializer.
//
// FIXME: Find a nicer place for this type definition.
// Unfortunately, it introduces circular dependencies when defined in one of
// the obvious places (like Event.h or RemoteSerializer.h)

using SourceID = std::uintptr_t;
constexpr SourceID SOURCE_LOCAL = 0;

// TODO: This is a temporary marker to flag events coming in via Broker.
// Those are remote events but we don't have any further peer information
// available for them (as the old communication code would have). Once we
// remove RemoteSerializer, we can turn the SourceID into a simple boolean
// indicating whether it's a local or remote event.
constexpr SourceID SOURCE_BROKER = 0xffffffff;

bool is_package_loader(const std::string& path);

extern void add_to_zeek_path(const std::string& dir);

/**
 * Wrapper class for functions like dirname(3) or basename(3) that won't
 * modify the path argument and may optionally abort execution on error.
 */
class SafePathOp
	{
public:
	std::string result;
	bool error;

protected:
	SafePathOp() : result(), error() { }

	void CheckValid(const char* result, const char* path, bool error_aborts);
	};

/**
 * Flatten a script name by replacing '/' path separators with '.'.
 * @param file A path to a Zeek script.  If it is a __load__.zeek, that part
 *             is discarded when constructing the flattened the name.
 * @param prefix A string to prepend to the flattened script name.
 * @return The flattened script name.
 */
std::string flatten_script_name(const std::string& name, const std::string& prefix = "");

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

/** Opens a Zeek script package.
 * @param path Location of a Zeek script package (a directory).  Will be changed
 *             to the path of the package's loader script.
 * @param mode An fopen(3) mode.
 * @return The return value of fopen(3) on the loader script or null if one
 *         doesn't exist.
 */
FILE* open_package(std::string& path, const std::string& mode = "r");

// This mimics the script-level function with the same name.
const char* log_file_name(const char* tag);

// Terminates processing gracefully, similar to pressing CTRL-C.
void terminate_processing();

// Sets the current status of the Zeek process to the given string.
// If the option --status-file has been set, this is written into
// the corresponding file.  Otherwise, the function is a no-op.
void set_processing_status(const char* status, const char* reason);

// Renames the given file to a new temporary name, and opens a new file with
// the original name. Returns new file or NULL on error. Inits rotate_info if
// given (open time is set network time).
extern FILE* rotate_file(const char* name, RecordVal* rotate_info);

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

	} // namespace detail

template <class T> void delete_each(T* t)
	{
	using iterator = typename T::iterator;
	for ( iterator it = t->begin(); it != t->end(); ++it )
		delete *it;
	}

inline void bytetohex(unsigned char byte, char* hex_out)
	{
	static constexpr char hex_chars[] = "0123456789abcdef";
	hex_out[0] = hex_chars[(byte & 0xf0) >> 4];
	hex_out[1] = hex_chars[byte & 0x0f];
	}

std::string get_unescaped_string(const std::string& str);

ODesc* get_escaped_string(ODesc* d, const char* str, size_t len, bool escape_all);
std::string get_escaped_string(const char* str, size_t len, bool escape_all);

inline std::string get_escaped_string(const std::string& str, bool escape_all)
	{
	return get_escaped_string(str.data(), str.length(), escape_all);
	}

std::vector<std::string>* tokenize_string(std::string_view input, std::string_view delim,
                                          std::vector<std::string>* rval = nullptr, int limit = 0);

std::vector<std::string_view> tokenize_string(std::string_view input, const char delim) noexcept;

extern char* copy_string(const char* s);
extern int streq(const char* s1, const char* s2);
extern bool starts_with(std::string_view s, std::string_view beginning);
extern bool ends_with(std::string_view s, std::string_view ending);

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
template <class T> int atoi_n(int len, const char* s, const char** end, int base, T& result);
extern char* uitoa_n(uint64_t value, char* str, int n, int base, const char* prefix = nullptr);
extern const char* strpbrk_n(size_t len, const char* s, const char* charset);
int strstr_n(const int big_len, const unsigned char* big, const int little_len,
             const unsigned char* little);

// Replaces all occurences of *o* in *s* with *n*.
extern std::string strreplace(const std::string& s, const std::string& o, const std::string& n);

// Remove all leading and trailing white space from string.
extern std::string strstrip(std::string s);

// Return a lower-cased version of the string.
extern std::string strtolower(const std::string& s);

// Return a upper-cased version of the string.
extern std::string strtoupper(const std::string& s);

extern int fputs(int len, const char* s, FILE* fp);
extern bool is_printable(const char* s, int len);

extern const char* fmt_bytes(const char* data, int len);

// Note: returns a pointer into a shared buffer.
extern const char* vfmt(const char* format, va_list args);
// Note: returns a pointer into a shared buffer.
extern const char* fmt(const char* format, ...) __attribute__((format(printf, 1, 2)));

// Returns true if path exists and is a directory.
bool is_dir(const std::string& path);

// Returns true if path exists and is a file.
bool is_file(const std::string& path);

extern int int_list_cmp(const void* v1, const void* v2);

extern const std::string& zeek_path();
extern const char* zeek_plugin_path();
extern const char* zeek_plugin_activate();
extern std::string zeek_prefixes();

class SafeDirname : public detail::SafePathOp
	{
public:
	explicit SafeDirname(const char* path, bool error_aborts = true);
	explicit SafeDirname(const std::string& path, bool error_aborts = true);

private:
	void DoFunc(const std::string& path, bool error_aborts = true);
	};

class SafeBasename : public detail::SafePathOp
	{
public:
	explicit SafeBasename(const char* path, bool error_aborts = true);
	explicit SafeBasename(const std::string& path, bool error_aborts = true);

private:
	void DoFunc(const std::string& path, bool error_aborts = true);
	};

std::string implode_string_vector(const std::vector<std::string>& v,
                                  const std::string& delim = "\n");

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

// Returns the current time.
// (In pseudo-realtime mode this is faked to be the start time of the
// trace plus the time interval Zeek has been running. To avoid this,
// call with real=true).
extern double current_time(bool real = false);

// Convert a time represented as a double to a timeval struct.
extern struct timeval double_to_timeval(double t);

// Return > 0 if tv_a > tv_b, 0 if equal, < 0 if tv_a < tv_b.
extern int time_compare(struct timeval* tv_a, struct timeval* tv_b);

// Returns the CPU time consumed to date.
extern double curr_CPU_time();

// Returns an integer that's very likely to be unique, even across Zeek
// instances. The integer can be drawn from different pools, which is helpful
// when the random number generator is seeded to be deterministic. In that
// case, the same sequence of integers is generated per pool.
#define UID_POOL_DEFAULT_INTERNAL 1
#define UID_POOL_DEFAULT_SCRIPT 2
#define UID_POOL_CUSTOM_SCRIPT 10 // First available custom script level pool.
extern uint64_t calculate_unique_id();
extern uint64_t calculate_unique_id(const size_t pool);

// Use for map's string keys.
struct ltstr
	{
	bool operator()(const char* s1, const char* s2) const { return strcmp(s1, s2) < 0; }
	};

constexpr size_t pad_size(size_t size)
	{
	// We emulate glibc here (values measured on Linux i386).
	// FIXME: We should better copy the portable value definitions from glibc.
	if ( size == 0 )
		return 0; // glibc allocated 16 bytes anyway.

	const int pad = 8;
	if ( size < 12 )
		return 2 * pad;

	return ((size + 3) / pad + 1) * pad;
	}

#define padded_sizeof(x) (zeek::util::pad_size(sizeof(x)))

// Like write() but handles interrupted system calls by restarting. Returns
// true if the write was successful, otherwise sets errno. This function is
// thread-safe as long as no two threads write to the same descriptor.
extern bool safe_write(int fd, const char* data, int len);

// Same as safe_write(), but for pwrite().
extern bool safe_pwrite(int fd, const unsigned char* data, size_t len, size_t offset);

// Like fsync() but handles interrupted system calls by retrying and
// aborts on unrecoverable errors.
extern bool safe_fsync(int fd);

// Wraps close(2) to emit error messages and abort on unrecoverable errors.
extern void safe_close(int fd);

// Versions of realloc/malloc which abort() on out of memory

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
	char* result = strncpy(dest, src, n - 1);
	dest[n - 1] = '\0';
	return result;
	}

// Memory alignment helpers.

inline bool is_power_of_2(zeek_uint_t x)
	{
	return ((x - 1) & x) == 0;
	}

// Rounds the given pointer up to the nearest multiple of the
// given size, if not already a multiple.
const void* memory_align(const void* ptr, size_t size);

// Rounds the given pointer up to the nearest multiple of the
// given size, padding the skipped region with 0 bytes.
void* memory_align_and_pad(void* ptr, size_t size);

// Returns offset rounded up so it can correctly align data of the given size.
int memory_size_align(size_t offset, size_t size);

// Returns total memory allocations and (if available) amount actually
// handed out by malloc.
extern void get_memory_usage(uint64_t* total, uint64_t* malloced);

// Class to be used as a third argument for STL maps to be able to use
// char*'s as keys. Otherwise the pointer values will be compared instead of
// the actual string values.
struct CompareString
	{
	bool operator()(char const* a, char const* b) const { return strcmp(a, b) < 0; }
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
 * Escapes bytes in a string that are not valid UTF8 characters with \xYY format. Used
 * by the JSON writer and BIF methods.
 * @param val the input string to be escaped
 * @return the escaped string
 */
std::string json_escape_utf8(const std::string& val, bool escape_printable_controls = true);

/**
 * Escapes bytes in a string that are not valid UTF8 characters with \xYY format. Used
 * by the JSON writer and BIF methods.
 * @param val the character data to be escaped
 * @param val_size the length of the character data
 * @return the escaped string
 */
std::string json_escape_utf8(const char* val, size_t val_size,
                             bool escape_printable_controls = true);

/**
 * Splits a string at all occurrences of a delimiter. Successive occurrences
 * of the delimiter will be split into multiple pieces.
 *
 * \note This function is not UTF8-aware.
 */
template <typename T> std::vector<T> split(T s, const T& delim)
	{
	// If there's no delimiter, return a copy of the existing string.
	if ( delim.empty() )
		return {T(s)};

	// If the delimiter won't fit in the string, just return a copy as well.
	if ( s.size() < delim.size() )
		return {T(s)};

	std::vector<T> l;

	const bool ends_in_delim = (s.substr(s.size() - delim.size()) == delim);

	do
		{
		size_t p = s.find(delim);
		l.push_back(s.substr(0, p));
		if ( p == std::string::npos )
			break;

		s = s.substr(p + delim.size());
		} while ( ! s.empty() );

	if ( ends_in_delim )
		l.emplace_back(T{});

	return l;
	}

/**
 * Specialized version of util::split that allows for differing string and delimiter types,
 * with the requirement that the delimiter must be of the same type as what is stored in the
 * string type. For example, this allows passing a std::string as the string to split with
 * a const char* delimiter.
 *
 * @param s the string to split
 * @param delim the delimiter to split the string on
 * @return a vector of containing the separate parts of the string.
 */
template <typename T, typename U = typename T::value_type*> std::vector<T> split(T s, U delim)
	{
	return split(s, T{delim});
	}

/**
 * Specialized version of util::split that takes a const char* string and delimiter.
 *
 * @param s the string to split
 * @param delim the delimiter to split the string on
 * @return a vector of string_view objects containing the separate parts of the string.
 */
inline std::vector<std::string_view> split(const char* s, const char* delim)
	{
	return split(std::string_view(s), std::string_view(delim));
	}

/**
 * Specialized version of util::split that takes a const wchar_t* string and delimiter.
 *
 * @param s the string to split
 * @param delim the delimiter to split the string on
 * @return a vector of wstring_view objects containing the separate parts of the string.
 */
inline std::vector<std::wstring_view> split(const wchar_t* s, const wchar_t* delim)
	{
	return split(std::wstring_view(s), std::wstring_view(delim));
	}

	} // namespace util
	} // namespace zeek
