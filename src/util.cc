// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"
#include "util-config.h"

#include "zeek/util.h"

#ifdef HAVE_DARWIN
#include <mach/task.h>
#include <mach/mach_init.h>
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
#include <libgen.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#if defined(HAVE_MALLINFO) || defined(HAVE_MALLINFO2)
# include <malloc.h>
#endif

#ifdef __linux__
#if __has_include(<sys/random.h>)
#define HAVE_GETRANDOM
#include <sys/random.h>
#endif
#endif

#include <string>
#include <array>
#include <vector>
#include <algorithm>
#include <iostream>

#include "zeek/3rdparty/doctest.h"

#include "zeek/Desc.h"
#include "zeek/Dict.h"
#include "zeek/digest.h"
#include "zeek/input.h"
#include "zeek/Obj.h"
#include "zeek/Val.h"
#include "zeek/NetVar.h"
#include "zeek/RunState.h"
#include "zeek/Reporter.h"
#include "zeek/iosource/Manager.h"
#include "zeek/iosource/PktSrc.h"
#include "zeek/ConvertUTF.h"
#include "zeek/Hash.h"

using namespace std;

extern const char* proc_status_file;

static bool can_read(const string& path)
	{
	return access(path.c_str(), R_OK) == 0;
	}

static string zeek_path_value;

namespace zeek::util {
namespace detail {

TEST_CASE("util extract_ip")
	{
	CHECK(extract_ip("[1.2.3.4]") == "1.2.3.4");
	CHECK(extract_ip("0x1.2.3.4") == "1.2.3.4");
	CHECK(extract_ip("[]") == "");
	}

/**
 * Return IP address without enclosing brackets and any leading 0x.  Also
 * trims leading/trailing whitespace.
 */
std::string extract_ip(const std::string& i)
	{
	std::string s(strstrip(i));

	if ( s.size() > 0 && s[0] == '[' )
		s.erase(0, 1);

	if ( s.size() > 1 && s.substr(0, 2) == "0x" )
		s.erase(0, 2);

	size_t pos = 0;
	if ( (pos = s.find(']')) != std::string::npos )
		s = s.substr(0, pos);

	return s;
	}

TEST_CASE("util extract_ip_and_len")
	{
	int len;
	std::string out = extract_ip_and_len("[1.2.3.4/24]", &len);
	CHECK(out == "1.2.3.4");
	CHECK(len == 24);

	out = extract_ip_and_len("0x1.2.3.4/32", &len);
	CHECK(out == "1.2.3.4");
	CHECK(len == 32);

	out = extract_ip_and_len("[]/abcd", &len);
	CHECK(out == "");
	CHECK(len == 0);

	out = extract_ip_and_len("[]/16", nullptr);
	CHECK(out == "");
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


static constexpr int parse_octal_digit(char ch) noexcept
	{
	if ( ch >= '0' && ch <= '7' )
		return ch - '0';
	else
		return -1;
	}

static constexpr int parse_hex_digit(char ch) noexcept
	{
	if ( ch >= '0' && ch <= '9' )
		return ch - '0';
	else if ( ch >= 'a' && ch <= 'f' )
		return 10 + ch - 'a';
	else if ( ch >= 'A' && ch <= 'F' )
		return 10 + ch - 'A';
	else
		return -1;
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

		// require at least one octal digit and parse at most three

		int result = parse_octal_digit(*s++);

		if ( result < 0 )
			{
			reporter->Error("bad octal escape: %s", start);
			return 0;
			}

		// second digit?
		int digit = parse_octal_digit(*s);

		if ( digit >= 0 )
			{
			result = (result << 3) | digit;
			++s;

			// third digit?
			digit = parse_octal_digit(*s);

			if ( digit >= 0 )
				{
				result = (result << 3) | digit;
				++s;
				}
			}

		return result;
		}

	case 'x':
		{ /* \x<hex> */
		const char* start = s;

		// Look at most 2 characters, so that "\x0ddir" -> "^Mdir".

		int result = parse_hex_digit(*s++);

		if ( result < 0 )
			{
			reporter->Error("bad hexadecimal escape: %s", start);
			return 0;
			}

		// second digit?
		int digit = parse_hex_digit(*s);

		if ( digit >= 0 )
			{
			result = (result << 4) | digit;
			++s;
			}

		return result;
		}

	default:
		return s[-1];
	}
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

	const auto path_components = tokenize_string(path, '/');

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
	if ( mkdir(dirname, 0777) == 0 )
		return true;

	auto mkdir_errno = errno;
	struct stat st;

	if ( stat(dirname, &st) == -1 )
		{
		// Show the original failure reason for mkdir() since nothing's there
		// or we can't even tell what is now.
		reporter->Warning("can't create directory %s: %s",
		                  dirname, strerror(mkdir_errno));
		return false;
		}

	if ( S_ISDIR(st.st_mode) )
		return true;

	reporter->Warning("%s exists but is not a directory", dirname);
	return false;
	}

void hmac_md5(size_t size, const unsigned char* bytes, unsigned char digest[16])
	{
	if ( ! zeek::detail::KeyedHash::seeds_initialized )
		reporter->InternalError("HMAC-MD5 invoked before the HMAC key is set");

	zeek::detail::internal_md5(bytes, size, digest);

	for ( int i = 0; i < 16; ++i )
		digest[i] ^= zeek::detail::KeyedHash::shared_hmac_md5_key[i];

	zeek::detail::internal_md5(digest, 16, digest);
	}

static bool read_random_seeds(const char* read_file, uint32_t* seed,
				std::array<uint32_t, zeek::detail::KeyedHash::SEED_INIT_SIZE>& buf)
	{
	FILE* f = nullptr;

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

	// Read seeds for hmac-md5/siphash/highwayhash.
	for ( auto &v : buf )
		{
		int tmp;
		if ( fscanf(f, "%u", &tmp) != 1 )
			{
			fclose(f);
			return false;
			}

		v = tmp;
		}

	fclose(f);
	return true;
	}

static bool write_random_seeds(const char* write_file, uint32_t seed,
				std::array<uint32_t, zeek::detail::KeyedHash::SEED_INIT_SIZE>& buf)
	{
	FILE* f = nullptr;

	if ( ! (f = fopen(write_file, "w+")) )
		{
		reporter->Warning("Could not create seed file '%s': %s",
		                  write_file, strerror(errno));
		return false;
		}

	fprintf(f, "%u\n", seed);

	for ( const auto &v: buf )
		fprintf(f, "%u\n", v);

	fclose(f);
	return true;
	}

static bool zeek_rand_determistic = false;
static long int zeek_rand_state = 0;
static bool first_seed_saved = false;
static unsigned int first_seed = 0;

static void zeek_srandom(unsigned int seed, bool deterministic)
	{
	zeek_rand_state = seed == 0 ? 1 : seed;
	zeek_rand_determistic = deterministic;

	srandom(seed);
	}

void seed_random(unsigned int seed)
	{
	if ( zeek_rand_determistic )
		zeek_rand_state = seed == 0 ? 1 : seed;
	else
		srandom(seed);
	}

void init_random_seed(const char* read_file, const char* write_file,
                      bool use_empty_seeds)
	{
	std::array<uint32_t, zeek::detail::KeyedHash::SEED_INIT_SIZE> buf = {};
	size_t pos = 0;	// accumulates entropy
	bool seeds_done = false;
	uint32_t seed = 0;

	if ( read_file )
		{
		if ( ! read_random_seeds(read_file, &seed, buf) )
			reporter->FatalError("Could not load seeds from file '%s'.\n",
			                     read_file);
		else
			seeds_done = true;
		}
	else if ( use_empty_seeds )
		seeds_done = true;

	if ( ! seeds_done )
		{
#ifdef HAVE_GETRANDOM
		// getrandom() guarantees reads up to 256 bytes are always successful,
		assert(sizeof(buf) < 256);
		auto nbytes = getrandom(buf.data(), sizeof(buf), 0);
		assert(nbytes == sizeof(buf));
		pos += nbytes / sizeof(uint32_t);
#else
		// Gather up some entropy.
		gettimeofday((struct timeval *)(buf.data() + pos), 0);
		pos += sizeof(struct timeval) / sizeof(uint32_t);

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
			int amt = read(fd, buf.data() + pos,
					sizeof(uint32_t) * (zeek::detail::KeyedHash::SEED_INIT_SIZE - pos));
			safe_close(fd);

			if ( amt > 0 )
				pos += amt / sizeof(uint32_t);
			else
				// Clear errno, which can be set on some
				// systems due to a lack of entropy.
				errno = 0;
			}
#endif

		if ( pos < zeek::detail::KeyedHash::SEED_INIT_SIZE )
			reporter->FatalError("Could not read enough random data. Wanted %d, got %zu",
			                     zeek::detail::KeyedHash::SEED_INIT_SIZE, pos);

		if ( ! seed )
			{
			for ( size_t i = 0; i < pos; ++i )
				{
				seed ^= buf[i];
				seed = (seed << 1) | (seed >> 31);
				}
			}
		else
			seeds_done = true;
		}

	zeek_srandom(seed, seeds_done);

	if ( ! first_seed_saved )
		{
		first_seed = seed;
		first_seed_saved = true;
		}

	if ( ! zeek::detail::KeyedHash::IsInitialized() )
		zeek::detail::KeyedHash::InitializeSeeds(buf);

	if ( write_file && ! write_random_seeds(write_file, seed, buf) )
		reporter->Error("Could not write seeds to file '%s'.\n",
		                write_file);
	}

unsigned int initial_seed()
	{
	return first_seed;
	}

bool have_random_seed()
	{
	return zeek_rand_determistic;
	}

constexpr uint32_t zeek_prng_mod = 2147483647;
constexpr uint32_t zeek_prng_max = zeek_prng_mod - 1;

long int max_random()
	{
	return zeek_rand_determistic ? zeek_prng_max : RAND_MAX;
	}

long int prng(long int state)
	{
	// Use our own simple linear congruence PRNG to make sure we are
	// predictable across platforms.  (Lehmer RNG, Schrage's method)
	// Note: the choice of "long int" storage type for the state is mostly
	// for parity with the possible return values of random().
	constexpr uint32_t m = zeek_prng_mod;
	constexpr uint32_t a = 16807;
	constexpr uint32_t q = m / a;
	constexpr uint32_t r = m % a;

	uint32_t rem = state % q;
	uint32_t div = state / q;
	int32_t s = a * rem;
	int32_t t = r * div;
	int32_t res = s - t;

	if ( res < 0 )
		res += m;

	return res;
	}

long int random_number()
	{
	if ( ! zeek_rand_determistic )
		return random(); // Use system PRNG.

	zeek_rand_state = detail::prng(zeek_rand_state);

	return zeek_rand_state;
	}

// Returns a 64-bit random string.
uint64_t rand64bit()
	{
	uint64_t base = 0;
	int i;

	for ( i = 1; i <= 4; ++i )
		base = (base<<16) | detail::random_number();
	return base;
	}

TEST_CASE("util is_package_loader")
	{
	CHECK(is_package_loader("/some/path/__load__.zeek") == true);
	CHECK(is_package_loader("/some/path/notload.zeek") == false);
	}

bool is_package_loader(const string& path)
	{
	string filename(std::move(SafeBasename(path).result));
	return ( filename == "__load__.zeek" );
	}

void add_to_zeek_path(const string& dir)
	{
	// Make sure path is initialized.
	zeek_path();

	zeek_path_value += string(":") + dir;
	}

FILE* open_package(string& path, const string& mode)
	{
	string arg_path = path;
	path.append("/__load__");

	string p = path + ".zeek";
	if ( can_read(p) )
		{
		path.append(".zeek");
		return open_file(path, mode);
		}

	path.append(".zeek");
	string package_loader = "__load__.zeek";
	reporter->Error("Failed to open package '%s': missing '%s' file",
	                arg_path.c_str(), package_loader.c_str());
	return nullptr;
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

TEST_CASE("util flatten_script_name")
	{
	CHECK(flatten_script_name("script", "some/path") == "some.path.script");
	CHECK(flatten_script_name("other/path/__load__.zeek", "some/path") == "some.path.other.path");
	CHECK(flatten_script_name("path/to/script", "") == "path.to.script");
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

TEST_CASE("util normalize_path")
	{
	CHECK(normalize_path("/1/2/3") == "/1/2/3");
	CHECK(normalize_path("/1/./2/3") == "/1/2/3");
	CHECK(normalize_path("/1/2/../3") == "/1/3");
	CHECK(normalize_path("1/2/3/") == "1/2/3");
	CHECK(normalize_path("1/2//3///") == "1/2/3");
	CHECK(normalize_path("~/zeek/testing") == "~/zeek/testing");
	CHECK(normalize_path("~jon/zeek/testing") == "~jon/zeek/testing");
	CHECK(normalize_path("~jon/./zeek/testing") == "~jon/zeek/testing");
	CHECK(normalize_path("~/zeek/testing/../././.") == "~/zeek");
	CHECK(normalize_path("./zeek") == "./zeek");
	CHECK(normalize_path("../zeek") == "../zeek");
	CHECK(normalize_path("../zeek/testing/..") == "../zeek");
	CHECK(normalize_path("./zeek/..") == ".");
	CHECK(normalize_path("./zeek/../..") == "..");
	CHECK(normalize_path("./zeek/../../..") == "../..");
	CHECK(normalize_path("./..") == "..");
	CHECK(normalize_path("../..") == "../..");
	CHECK(normalize_path("/..") == "/..");
	CHECK(normalize_path("~/..") == "~/..");
	CHECK(normalize_path("/../..") == "/../..");
	CHECK(normalize_path("~/../..") == "~/../..");
	CHECK(normalize_path("zeek/..") == "");
	CHECK(normalize_path("zeek/../..") == "..");
	}

string normalize_path(std::string_view path)
	{
	if ( path.find("/.") == std::string_view::npos &&
	     path.find("//") == std::string_view::npos )
		{
		// no need to normalize anything
		if ( path.size() > 1 && path.back() == '/' )
			path.remove_suffix(1);
		return std::string(path);
		}

	size_t n;
	vector<std::string_view> final_components;
	string new_path;
	new_path.reserve(path.size());

	if ( ! path.empty() && path[0] == '/' )
		new_path = "/";

	const auto components = tokenize_string(path, '/');
	final_components.reserve(components.size());

	for ( auto it = components.begin(); it != components.end(); ++it )
		{
		if ( *it == "" ) continue;
		if ( *it == "." && it != components.begin() ) continue;

		final_components.push_back(*it);

		if ( *it == ".." )
			{
			auto cur_idx = final_components.size() - 1;

			if ( cur_idx != 0 )
				{
				auto last_idx = cur_idx - 1;
				auto& last_component = final_components[last_idx];

				if ( last_component == "/" || last_component == "~" ||
				     last_component == ".." )
					continue;

				if ( last_component == "." )
					{
					last_component = "..";
					final_components.pop_back();
					}
				else
					{
					final_components.pop_back();
					final_components.pop_back();
					}
				}
			}
		}

	for ( auto it = final_components.begin(); it != final_components.end(); ++it )
		{
		new_path.append(*it);
		new_path.append("/");
		}

	if ( new_path.size() > 1 && new_path[new_path.size() - 1] == '/' )
		new_path.erase(new_path.size() - 1);

	return new_path;
	}

string without_zeekpath_component(std::string_view path)
	{
	string rval = normalize_path(path);

	const auto paths = tokenize_string(zeek_path(), ':');

	for ( size_t i = 0; i < paths.size(); ++i )
		{
		string common = normalize_path(paths[i]);

		if ( rval.find(common) != 0 )
			continue;

		// Found the containing directory.
		std::string_view v(rval);
		v.remove_prefix(common.size());

		// Remove leading path separators.
		while ( !v.empty() && v.front() == '/' )
			v.remove_prefix(1);

		return std::string(v);
		}

	return rval;
	}

std::string get_exe_path(const std::string& invocation)
	{
	if ( invocation.empty() )
		return "";

	if ( invocation[0] == '/' || invocation[0] == '~' )
		// Absolute path
		return invocation;

	if ( invocation.find('/') != std::string::npos )
		{
		// Relative path
		char cwd[PATH_MAX];

		if ( ! getcwd(cwd, sizeof(cwd)) )
			{
			fprintf(stderr, "failed to get current directory: %s\n",
			        strerror(errno));
			exit(1);
			}

		return std::string(cwd) + "/" + invocation;
		}

	auto path = getenv("PATH");

	if ( ! path )
		return "";

	return find_file(invocation, path);
	}

FILE* rotate_file(const char* name, RecordVal* rotate_info)
	{
	// Build file names.
	const int buflen = strlen(name) + 128;

	auto newname_buf = std::make_unique<char[]>(buflen);
	auto tmpname_buf = std::make_unique<char[]>(buflen + 4);
	auto newname = newname_buf.get();
	auto tmpname = tmpname_buf.get();

	snprintf(newname, buflen, "%s.%d.%.06f.tmp",
	         name, getpid(), run_state::network_time);
	newname[buflen-1] = '\0';
	strcpy(tmpname, newname);
	strcat(tmpname, ".tmp");

	// First open the new file using a temporary name.
	FILE* newf = fopen(tmpname, "w");
	if ( ! newf )
		{
		reporter->Error("rotate_file: can't open %s: %s", tmpname, strerror(errno));
		return nullptr;
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
		return nullptr;
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
		rotate_info->Assign(0, name);
		rotate_info->Assign(1, newname);
		rotate_info->AssignTime(2, run_state::network_time);
		rotate_info->AssignTime(3, run_state::network_time);
		}

	return newf;
	}

const char* log_file_name(const char* tag)
	{
	const char* env = getenv("ZEEK_LOG_SUFFIX");
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
	double delta_t = startofday + base +
		ceil((current - startofday - base) / interval) * interval -
			current;
	return delta_t > 0.0 ? delta_t: interval;
	}

void terminate_processing()
	{
	if ( ! run_state::terminating )
		raise(SIGTERM);
	}

void set_processing_status(const char* status, const char* reason)
	{
	// This function can be called from a signal context, so we have to
	// make sure to only call reentrant & async-signal-safe functions,
	// and to restore errno afterwards.

	if ( ! proc_status_file )
		return;

	auto write_str = [](int fd, const char* s)
		{
		int len = strlen(s);
		while ( len )
			{
			int n = write(fd, s, len);

			if ( n < 0 && errno != EINTR && errno != EAGAIN )
				// Ignore errors, as they're too difficult to
				// safely report here.
				break;

			s += n;
			len -= n;
			}
		};

	auto report_error_with_errno = [&](const char* msg)
		{
		// strerror_r() is not async-signal-safe, hence we don't do
		// the translation from errno to string.
		auto errno_str = std::to_string(errno);
		write_str(2, msg);
		write_str(2, " '");
		write_str(2, proc_status_file);
		write_str(2, "': ");
		write_str(2, errno_str.c_str());
		write_str(2, " [");
		write_str(2, status);
		write_str(2, "]\n");
		};

	int old_errno = errno;

	int fd = open(proc_status_file, O_CREAT | O_WRONLY | O_TRUNC, 0777);
	if ( fd < 0 )
		{
		report_error_with_errno("Failed to open process status file");
		errno = old_errno;
		return;
		}

	write_str(fd, status);
	write_str(fd, " [");
	write_str(fd, reason);
	write_str(fd, "]\n");

	if ( close(fd) < 0 && errno != EINTR )
			{
			report_error_with_errno("Failed to close process status file");
			abort(); // same as safe_close()
			}

	errno = old_errno;
	}

void set_thread_name(const char* name, pthread_t tid)
	{
#ifdef HAVE_LINUX
	prctl(PR_SET_NAME, name, 0, 0, 0);
#endif

#ifdef __APPLE__
	pthread_setname_np(name);
#endif

#ifdef __FreeBSD__
	pthread_set_name_np(tid, name);
#endif
	}

} // namespace detail

TEST_CASE("util get_unescaped_string")
	{
	CHECK(get_unescaped_string("abcde") == "abcde");
	CHECK(get_unescaped_string("\\x41BCD\\x45") == "ABCDE");
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

TEST_CASE("util get_escaped_string")
	{
	SUBCASE("returned ODesc")
		{
		ODesc* d = get_escaped_string(nullptr, "a bcd\n", 6, false);
		CHECK(strcmp(d->Description(), "a\\x20bcd\\x0a") == 0);
		delete d;
		}

	SUBCASE("provided ODesc")
		{
		ODesc d2;
		get_escaped_string(&d2, "ab\\e", 4, true);
		CHECK(strcmp(d2.Description(), "\\x61\\x62\\\\\\x65") == 0);
		}

	SUBCASE("std::string versions")
		{
		std::string s = get_escaped_string("a b c", 5, false);
		CHECK(s == "a\\x20b\\x20c");

		s = get_escaped_string("d e", false);
		CHECK(s == "d\\x20e");
		}
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
		return nullptr;

	char* c = new char[strlen(s)+1];
	strcpy(c, s);
	return c;
	}

TEST_CASE("util streq")
	{
	CHECK(streq("abcd", "abcd") == true);
	CHECK(streq("abcd", "efgh") == false);
	}

int streq(const char* s1, const char* s2)
	{
	return ! strcmp(s1, s2);
	}

bool starts_with(std::string_view s, std::string_view beginning)
	{
	if ( beginning.size() > s.size() )
		return false;

	return std::equal(beginning.begin(), beginning.end(), s.begin());
	}

TEST_CASE("util starts_with")
	{
	CHECK(starts_with("abcde", "ab") == true);
	CHECK(starts_with("abcde", "de") == false);
	CHECK(starts_with("abcde", "abcedf") == false);
	}

bool ends_with(std::string_view s, std::string_view ending)
	{
	if ( ending.size() > s.size() )
		return false;

	return std::equal(ending.rbegin(), ending.rend(), s.rbegin());
	}

TEST_CASE("util ends_with")
	{
	CHECK(ends_with("abcde", "de") == true);
	CHECK(ends_with("abcde", "fg") == false);
	CHECK(ends_with("abcde", "abcedf") == false);
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

TEST_CASE("util get_word")
	{
	char orig[10];
	strcpy(orig, "two words");

	SUBCASE("get first word")
		{
		char* a = (char*)orig;
		char* b = get_word(a);

		CHECK(strcmp(a, "words") == 0);
		CHECK(strcmp(b, "two") == 0);
		}

	SUBCASE("get length of first word")
		{
		int len = strlen(orig);
		int len2;
		const char* b = nullptr;
		get_word(len, orig, len2, b);
		CHECK(len2 == 3);
		}
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

TEST_CASE("util to_upper")
	{
	char a[10];
	strcpy(a, "aBcD");
	to_upper(a);
	CHECK(strcmp(a, "ABCD") == 0);

	std::string b = "aBcD";
	CHECK(to_upper(b) == "ABCD");
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

TEST_CASE("util strpbrk_n")
	{
	const char* s = "abcdef";
	const char* o = strpbrk_n(5, s, "gc");
	CHECK(strcmp(o, "cdef") == 0);

	const char* f = strpbrk_n(5, s, "xyz");
	CHECK(f == nullptr);
	}

// Same as strpbrk except that s is not NUL-terminated, but limited by
// len. Note that '\0' is always implicitly contained in charset.
const char* strpbrk_n(size_t len, const char* s, const char* charset)
	{
	for ( const char* p = s; p < s + len; ++p )
		if ( strchr(charset, *p) )
			return p;

	return nullptr;
	}

#ifndef HAVE_STRCASESTR

TEST_CASE("util strcasestr")
	{
	const char* s = "this is a string";
	const char* out = strcasestr(s, "is");
	CHECK(strcmp(out, "is a string") == 0);

	const char* out2 = strcasestr(s, "IS");
	CHECK(strcmp(out2, "is a string") == 0);

	const char* out3 = strcasestr(s, "not there");
	CHECK(strcmp(out2, s) == 0);
	}

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

TEST_CASE("util atoi_n")
	{
	const char* dec = "12345";
	int val;

	CHECK(atoi_n(strlen(dec), dec, nullptr, 10, val) == 1);
	CHECK(val == 12345);

	const char* hex = "12AB";
	CHECK(atoi_n(strlen(hex), hex, nullptr, 16, val) == 1);
	CHECK(val == 0x12AB);

	const char* fail = "XYZ";
	CHECK(atoi_n(strlen(fail), fail, nullptr, 10, val) == 0);
	}

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

TEST_CASE("util uitoa_n")
	{
	int val = 12345;
	char str[20];
	const char* result = uitoa_n(val, str, 20, 10, "pref: ");
	// TODO: i'm not sure this is the correct output. was it supposed to reverse the digits?
	CHECK(strcmp(str, "pref: 54321") == 0);
	}

char* uitoa_n(uint64_t value, char* str, int n, int base, const char* prefix)
	{
	static constexpr char dig[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

	assert(n);

	int i = 0;
	uint64_t v;
	char* p, *q;
	char c;

	if ( prefix )
		{
		strncpy(str, prefix, n-1);
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

TEST_CASE("util strstr_n")
	{
	const u_char* s = reinterpret_cast<const u_char*>("this is a string");
	int out = strstr_n(16, s, 3, reinterpret_cast<const u_char*>("str"));
	CHECK(out == 10);

	out = strstr_n(16, s, 17, reinterpret_cast<const u_char*>("is"));
	CHECK(out == -1);

	out = strstr_n(16, s, 2, reinterpret_cast<const u_char*>("IS"));
	CHECK(out == -1);

	out = strstr_n(16, s, 9, reinterpret_cast<const u_char*>("not there"));
	CHECK(out == -1);
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

TEST_CASE("util is_printable")
	{
	CHECK(is_printable("abcd", 4) == true);
	CHECK(is_printable("ab\0d", 4) == false);
	}

bool is_printable(const char* s, int len)
	{
	while ( --len >= 0 )
		if ( ! isprint(*s++) )
			return false;
	return true;
	}

TEST_CASE("util strtolower")
	{
	const char* a = "aBcD";
	CHECK(strtolower(a) == "abcd");

	std::string b = "aBcD";
	CHECK(strtolower(b) == "abcd");
	}

std::string strtolower(const std::string& s)
	{
	std::string t = s;
	std::transform(t.begin(), t.end(), t.begin(), ::tolower);
	return t;
	}

TEST_CASE("util fmt_bytes")
	{
	const char* a = "abcd";
	const char* af = fmt_bytes(a, 4);
	CHECK(strcmp(a, af) == 0);

	const char* b = "abc\0abc";
	const char* bf = fmt_bytes(b, 7);
	CHECK(strcmp(bf, "abc\\x00abc") == 0);

	const char* cf = fmt_bytes(a, 3);
	CHECK(strcmp(cf, "abc") == 0);
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

const char* vfmt(const char* format, va_list al)
	{
	static char* buf = nullptr;
	static unsigned int buf_len = 1024;

	if ( ! buf )
		buf = (char*) safe_malloc(buf_len);

	va_list alc;
	va_copy(alc, al);
	int n = vsnprintf(buf, buf_len, format, al);

	if ( (unsigned int) n >= buf_len )
		{ // Not enough room, grow the buffer.
		buf_len = n + 32;
		buf = (char*) safe_realloc(buf, buf_len);

		n = vsnprintf(buf, buf_len, format, alc);

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
	auto rval = vfmt(format, al);
	va_end(al);
	return rval;
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

TEST_CASE("util strreplace")
	{
	string s = "this is not a string";
	CHECK(strreplace(s, "not", "really") == "this is really a string");
	CHECK(strreplace(s, "not ", "") == "this is a string");
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

TEST_CASE("util strstrip")
	{
	string s = "  abcd";
	CHECK(strstrip(s) == "abcd");

	s = "abcd  ";
	CHECK(strstrip(s) == "abcd");

	s = "  abcd  ";
	CHECK(strstrip(s) == "abcd");
	}

std::string strstrip(std::string s)
	{
	auto notspace = [](unsigned char c) { return ! std::isspace(c); };
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), notspace));
	s.erase(std::find_if(s.rbegin(), s.rend(), notspace).base(), s.end());
	return s;
	}

int int_list_cmp(const void* v1, const void* v2)
	{
	std::intptr_t i1 = *(std::intptr_t*) v1;
	std::intptr_t i2 = *(std::intptr_t*) v2;

	if ( i1 < i2 )
		return -1;
	else if ( i1 == i2 )
		return 0;
	else
		return 1;
	}

const std::string& zeek_path()
	{
	if ( zeek_path_value.empty() )
		{
		const char* path = getenv("ZEEKPATH");

		if ( ! path )
			path = DEFAULT_ZEEKPATH;

		zeek_path_value = path;
		}

	return zeek_path_value;
	}

const char* zeek_plugin_path()
	{
	const char* path = getenv("ZEEK_PLUGIN_PATH");

	if ( ! path )
		path = BRO_PLUGIN_INSTALL_PATH;

	return path;
	}

const char* zeek_plugin_activate()
	{
	const char* names = getenv("ZEEK_PLUGIN_ACTIVATE");

	if ( ! names )
		names = "";

	return names;
	}

string zeek_prefixes()
	{
	string rval;

	for ( const auto& prefix : zeek::detail::zeek_script_prefixes )
		{
		if ( ! rval.empty() )
			rval.append(":");
		rval.append(prefix);
		}

	return rval;
	}

FILE* open_file(const string& path, const string& mode)
	{
	if ( path.empty() )
		return nullptr;

	FILE* rval = fopen(path.c_str(), mode.c_str());

	if ( ! rval )
		{
		char buf[256];
		zeek_strerror_r(errno, buf, sizeof(buf));
		reporter->Error("Failed to open file %s: %s", filename, buf);
		}

	return rval;
	}

TEST_CASE("util path ops")
	{
	SUBCASE("SafeDirname")
		{
		SafeDirname d("/this/is/a/path", false);
		CHECK(d.result == "/this/is/a");

		SafeDirname d2("invalid", false);
		CHECK(d2.result == ".");

		SafeDirname d3("./filename", false);
		CHECK(d2.result == ".");
		}

	SUBCASE("SafeBasename")
		{
		SafeBasename b("/this/is/a/path", false);
		CHECK(b.result == "path");
		CHECK(! b.error);

		SafeBasename b2("justafile", false);
		CHECK(b2.result == "justafile");
		CHECK(! b2.error);
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

TEST_CASE("util implode_string_vector")
	{
	std::vector<std::string> v = { "a", "b", "c" };
	CHECK(implode_string_vector(v, ",") == "a,b,c");
	CHECK(implode_string_vector(v, "") == "abc");

	v.clear();
	CHECK(implode_string_vector(v, ",") == "");
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

TEST_CASE("util tokenize_string")
	{
	auto v = tokenize_string("/this/is/a/path", "/", nullptr);
	CHECK(v->size() == 5);
	CHECK(*v == vector<string>({ "", "this", "is", "a", "path" }));
	delete v;

	std::vector<std::string> v2;
	tokenize_string("/this/is/path/2", "/", &v2);
	CHECK(v2.size() == 5);
	CHECK(v2 == vector<string>({ "", "this", "is", "path", "2" }));

	v2.clear();
	tokenize_string("/wrong/delim", ",", &v2);
	CHECK(v2.size() == 1);

	auto svs = tokenize_string("one,two,three,four,", ',');
	std::vector<std::string_view> expect{"one", "two", "three", "four", ""};
	CHECK(svs == expect);

	auto letters = tokenize_string("a--b--c--d", "--");
	CHECK(*letters == vector<string>({ "a", "b", "c", "d" }));
	delete letters;
	}

vector<string>* tokenize_string(std::string_view input, std::string_view delim,
                                vector<string>* rval, int limit)
	{
	if ( ! rval )
		rval = new vector<string>();

	size_t pos = 0;
	size_t n;
	auto found = 0;

	while ( (n = input.find(delim, pos)) != string::npos )
		{
		++found;
		rval->emplace_back(input.substr(pos, n - pos));
		pos = n + delim.size();

		if ( limit && found == limit )
			break;
		}

	rval->emplace_back(input.substr(pos));
	return rval;
	}

vector<std::string_view> tokenize_string(std::string_view input, const char delim) noexcept
	{
	vector<std::string_view> rval;

	size_t pos = 0;
	size_t n;

	while ( (n = input.find(delim, pos)) != string::npos )
		{
		rval.emplace_back(input.substr(pos, n - pos));
		pos = n + 1;
		}

	rval.emplace_back(input.substr(pos));
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

string find_script_file(const string& filename, const string& path_set)
	{
	vector<string> paths;
	tokenize_string(path_set, ":", &paths);

	vector<string> ext = {".zeek"};

	for ( size_t n = 0; n < paths.size(); ++n )
		{
		string f = find_file_in_path(filename, paths[n], ext);

		if ( ! f.empty() )
			return f;
		}

	return string();
	}

RETSIGTYPE sig_handler(int signo);

double current_time(bool real)
	{
	struct timeval tv;
	if ( gettimeofday(&tv, 0) < 0 )
		reporter->InternalError("gettimeofday failed in current_time()");

	double t = double(tv.tv_sec) + double(tv.tv_usec) / 1e6;

	if ( ! run_state::pseudo_realtime || real || ! iosource_mgr || ! iosource_mgr->GetPktSrc() )
		return t;

	// This obviously only works for a single source ...
	iosource::PktSrc* src = iosource_mgr->GetPktSrc();

	if ( run_state::is_processing_suspended() )
		return run_state::current_packet_timestamp();

	// We don't scale with pseudo_realtime here as that would give us a
	// jumping real-time.
	return run_state::current_packet_timestamp() + (t - run_state::current_packet_wallclock());
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
	UIDEntry(const uint64_t i) : key(i, 0), needs_init(false) { }

	struct UIDKey {
		UIDKey(uint64_t i, uint64_t c) : instance(i), counter(c) { }
		uint64_t instance;
		uint64_t counter;
	} key;

	bool needs_init;
};

static std::vector<UIDEntry> uid_pool;

uint64_t calculate_unique_id()
	{
	return calculate_unique_id(UID_POOL_DEFAULT_INTERNAL);
	}

uint64_t calculate_unique_id(size_t pool)
	{
	uint64_t uid_instance = 0;

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
		if ( ! detail::have_random_seed() )
			{
			// If we don't need deterministic output (as
			// indicated by a set seed), we calculate the
			// instance ID by hashing something likely to be
			// globally unique.
			struct {
				char hostname[120];
				uint64_t pool;
				struct timeval time;
				pid_t pid;
				int rnd;
			} unique;

			memset(&unique, 0, sizeof(unique)); // Make valgrind happy.
			gethostname(unique.hostname, 120);
			unique.hostname[sizeof(unique.hostname)-1] = '\0';
			gettimeofday(&unique.time, 0);
			unique.pool = (uint64_t) pool;
			unique.pid = getpid();
			unique.rnd = static_cast<int>(detail::random_number());

			uid_instance = zeek::detail::HashKey::HashBytes(&unique, sizeof(unique));
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
	return zeek::detail::HashKey::HashBytes(&(uid_pool[pool].key), sizeof(uid_pool[pool].key));
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

			char buf[128];
			zeek_strerror_r(errno, buf, sizeof(buf));
			fprintf(stderr, "safe_write error: %d (%s)\n", errno, buf);
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

			char buf[128];
			zeek_strerror_r(errno, buf, sizeof(buf));
			fprintf(stderr, "safe_write error: %d (%s)\n", errno, buf);
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
		zeek_strerror_r(errno, buf, sizeof(buf));
		fprintf(stderr, "safe_close error %d: %s\n", errno, buf);
		abort();
		}
	}

void get_memory_usage(uint64_t* total, uint64_t* malloced)
	{
	uint64_t ret_total;

#if defined(HAVE_MALLINFO2) || defined(HAVE_MALLINFO)
#ifdef HAVE_MALLINFO2
	struct mallinfo2 mi = mallinfo2();
#else
	struct mallinfo mi = mallinfo();
#endif
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
		printf("%.6f malloc %x %d\n", run_state::network_time, v, t);
	return v;
	}

void* debug_realloc(void* v, size_t t)
	{
	v = realloc(v, t);
	if ( malloc_debug )
		printf("%.6f realloc %x %d\n", run_state::network_time, v, t);
	return v;
	}

void debug_free(void* v)
	{
	if ( malloc_debug )
		printf("%.6f free %x\n", run_state::network_time, v);
	free(v);
	}

void* operator new(size_t t)
	{
	void* v = malloc(t);
	if ( malloc_debug )
		printf("%.6f new %x %d\n", run_state::network_time, v, t);
	return v;
	}

void* operator new[](size_t t)
	{
	void* v = malloc(t);
	if ( malloc_debug )
		printf("%.6f new[] %x %d\n", run_state::network_time, v, t);
	return v;
	}

void operator delete(void* v)
	{
	if ( malloc_debug )
		printf("%.6f delete %x\n", run_state::network_time, v);
	free(v);
	}

void operator delete[](void* v)
	{
	if ( malloc_debug )
		printf("%.6f delete %x\n", run_state::network_time, v);
	free(v);
	}

#endif

TEST_CASE("util canonify_name")
	{
	CHECK(canonify_name("file name") == "FILE_NAME");
	}

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

void zeek_strerror_r(int zeek_errno, char* buf, size_t buflen)
	{
	auto res = strerror_r(zeek_errno, buf, buflen);
	// GNU vs. XSI flavors make it harder to use strerror_r.
	strerror_r_helper(res, buf, buflen);
	}

char* zeekenv(const char* name)
	{
	return getenv(name);
	}

static string json_escape_byte(char c)
	{
	char hex[2] = {'0', '0'};
	bytetohex(c, hex);

	string result = "\\x";
	result.append(hex, 2);

	return result;
	}

TEST_CASE("util json_escape_utf8")
	{
	CHECK(json_escape_utf8("string") == "string");
	CHECK(json_escape_utf8("string\n") == "string\n");
	CHECK(json_escape_utf8("string\x82") == "string\\x82");
	CHECK(json_escape_utf8("\x07\xd4\xb7o") == "\\x07\\xd4\\xb7o");

	// These strings are duplicated from the scripts.base.frameworks.logging.ascii-json-utf8 btest

	// Valid ASCII and valid ASCII control characters
	CHECK(json_escape_utf8("a") == "a");
	CHECK(json_escape_utf8("\b\f\n\r\t\x00\x15") == "\b\f\n\r\t\x00\x15");

	// Table 3-7 in https://www.unicode.org/versions/Unicode12.0.0/ch03.pdf describes what is
	// valid and invalid for the tests below

	// Valid 2 Octet Sequence
	CHECK(json_escape_utf8("\xc3\xb1") == "\xc3\xb1");

	// Invalid 2 Octet Sequence
	CHECK(json_escape_utf8("\xc3\x28") == "\\xc3(");
	CHECK(json_escape_utf8("\xc0\x81") == "\\xc0\\x81");
	CHECK(json_escape_utf8("\xc1\x81") == "\\xc1\\x81");
	CHECK(json_escape_utf8("\xc2\xcf") == "\\xc2\\xcf");

	// Invalid Sequence Identifier
	CHECK(json_escape_utf8("\xa0\xa1") == "\\xa0\\xa1");

	// Valid 3 Octet Sequence
	CHECK(json_escape_utf8("\xe2\x82\xa1") == "\xe2\x82\xa1");
	CHECK(json_escape_utf8("\xe0\xa3\xa1") == "\xe0\xa3\xa1");

	// Invalid 3 Octet Sequence (in 2nd Octet)
	CHECK(json_escape_utf8("\xe0\x80\xa1") == "\\xe0\\x80\\xa1");
	CHECK(json_escape_utf8("\xe2\x28\xa1") == "\\xe2(\\xa1");
	CHECK(json_escape_utf8("\xed\xa0\xa1") == "\\xed\\xa0\\xa1");

	// Invalid 3 Octet Sequence (in 3rd Octet)
	CHECK(json_escape_utf8("\xe2\x82\x28") == "\\xe2\\x82(");

	// Valid 4 Octet Sequence
	CHECK(json_escape_utf8("\xf0\x90\x8c\xbc") == "\xf0\x90\x8c\xbc");
	CHECK(json_escape_utf8("\xf1\x80\x8c\xbc") == "\xf1\x80\x8c\xbc");
	CHECK(json_escape_utf8("\xf4\x80\x8c\xbc") == "\xf4\x80\x8c\xbc");

	// Invalid 4 Octet Sequence (in 2nd Octet)
	CHECK(json_escape_utf8("\xf0\x80\x8c\xbc") == "\\xf0\\x80\\x8c\\xbc");
	CHECK(json_escape_utf8("\xf2\x28\x8c\xbc") == "\\xf2(\\x8c\\xbc");
	CHECK(json_escape_utf8("\xf4\x90\x8c\xbc") == "\\xf4\\x90\\x8c\\xbc");

	// Invalid 4 Octet Sequence (in 3rd Octet)
	CHECK(json_escape_utf8("\xf0\x90\x28\xbc") == "\\xf0\\x90(\\xbc");

	// Invalid 4 Octet Sequence (in 4th Octet)
	CHECK(json_escape_utf8("\xf0\x28\x8c\x28") == "\\xf0(\\x8c(");

	// Invalid 4 Octet Sequence (too short)
	CHECK(json_escape_utf8("\xf4\x80\x8c") == "\\xf4\\x80\\x8c");
	CHECK(json_escape_utf8("\xf0") == "\\xf0");

	// Private Use Area (E000-F8FF) are always invalid
	CHECK(json_escape_utf8("\xee\x8b\xa0") == "\\xee\\x8b\\xa0");

	// Valid UTF-8 character followed by an invalid one
	CHECK(json_escape_utf8("\xc3\xb1\xc0\x81") == "\\xc3\\xb1\\xc0\\x81");
	}

static bool check_ok_utf8(const unsigned char* start, const unsigned char* end)
	{
	// There's certain blocks of UTF-8 that we don't want, but the easiest way to find
	// them is to convert to UTF-32 and then compare. This is annoying, but it also calls
	// isLegalUTF8Sequence along the way so go with it.
	std::array<UTF32, 2> output;
	UTF32* output2 = output.data();
	auto result = ConvertUTF8toUTF32(&start, end, &output2, output2+1, strictConversion);
	if ( result != conversionOK )
		return false;

	if ( ( output[0] <= 0x001F ) || ( output[0] == 0x007F ) ||
	     ( output[0] >= 0x0080 && output[0] <= 0x009F ) )
		// Control characters
		return false;
	else if ( output[0] >= 0xE000 && output[0] <= 0xF8FF )
		// Private Use Area
		return false;
	else if ( output[0] >= 0xFFF0 && output[0] <= 0xFFFF )
		// Specials Characters
		return false;

	return true;
	}

string json_escape_utf8(const string& val)
	{
	auto val_data = reinterpret_cast<const unsigned char*>(val.c_str());
	auto val_size = val.length();

	// Reserve at least the size of the existing string to avoid resizing the string in the best-case
	// scenario where we don't have any multi-byte characters. We keep two versions of this string:
	// one that has a valid utf8 string and one that has a fully-escaped version. The utf8 string gets
	// returned if all of the characters were valid utf8 sequences, but it will fall back to the
	// escaped version otherwise. This uses slightly more memory but it avoids looping through all
	// of the characters a second time in the case of a bad utf8 sequence.
	string utf_result;
	utf_result.reserve(val_size);
	string escaped_result;
	escaped_result.reserve(val_size);

	bool found_bad = false;
	size_t idx = 0;
	while ( idx < val_size )
		{
		const char ch = val[idx];

		// Normal ASCII characters plus a few of the control characters can be inserted directly. The
		// rest of the control characters should be escaped as regular bytes.
		if ( ( ch >= 32 && ch < 127 ) ||
		       ch == '\b' || ch == '\f' || ch == '\n' || ch == '\r' || ch == '\t' )
			{
			if ( ! found_bad )
				utf_result.push_back(ch);

			escaped_result.push_back(ch);
			++idx;
			continue;
			}
		else if ( found_bad )
			{
			// If we already found a bad UTF8 character (see check_ok_utf8) just insert the bytes
			// as escaped characters into the escaped result and move on.
			escaped_result.append(json_escape_byte(ch));
			++idx;
			continue;
			}

		// If we haven't found a bad UTF-8 character yet, check to see if the next one starts a
		// UTF-8 character. If not, we'll mark that we're on a bad result. Otherwise we'll go
		// ahead and insert this character and continue.
		if ( ! found_bad )
			{
			// Find out how long the next character should be.
			unsigned int char_size = getNumBytesForUTF8(ch);

			// If we don't have enough data for this character or it's an invalid sequence,
			// insert the one escaped byte into the string and go to the next character.
			if ( idx+char_size > val_size ||
			     ! check_ok_utf8(val_data + idx, val_data + idx + char_size) )
				{
				found_bad = true;
				escaped_result.append(json_escape_byte(ch));
				++idx;
				continue;
				}
			else
				{
				for ( unsigned int i = 0; i < char_size; i++ )
					escaped_result.append(json_escape_byte(val[idx+i]));
				utf_result.append(val, idx, char_size);
				idx += char_size;
				}
			}
		}

	if ( found_bad )
		return escaped_result;
	else
		return utf_result;
	}

} // namespace zeek::util

extern "C" void out_of_memory(const char* where)
	{
	fprintf(stderr, "out of memory in %s.\n", where);

	if ( zeek::reporter )
		// Guess that might fail here if memory is really tight ...
		zeek::reporter->FatalError("out of memory in %s.\n", where);

	abort();
	}
