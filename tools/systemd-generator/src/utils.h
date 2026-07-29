// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <filesystem>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace zeek::detail {

/**
 * Inplace ltrim of \a s.
 */
void ltrim(std::string& s);

/**
 * Inplace rtrim of \a s.
 */
void rtrim(std::string& s);

/**
 * Inplace trim of \a s.
 */
void trim(std::string& s);

/**
 * Inplace tolower of \a s.
 */
void tolower(std::string& s);

/**
 * Wrapper for std::from_chars()
 */
std::optional<int> parse_int(std::string_view sv);

/**
 *Split \a v by \a delim into a vector of string views.
 */
std::vector<std::string_view> split(std::string_view v, char delim);

/**
 * " ".join(...) in C++, meh.
 */
std::string join(std::span<const std::string> args, const std::string& sep = " ");

/**
 * Same as join() for strings, but taking paths instead.
 */
std::string join(std::span<const std::filesystem::path> paths, const std::string& sep = " ");

/**
 * Replace \a s with with all occurrences of ${var} replaced with the values of var in the map \a vars.
 */
std::optional<std::string> substitute_vars(const std::string& s, const std::map<std::string, std::string>& vars);

/**
 * Returns true if the given string is a valid IPv4 address, or IPv6 address with brackets around it.
 */
bool is_valid_ip(const std::string& s);

/**
 * Parses a CPU list via the constructor.
 *
 * Some examples:
 *
 *   1,2,3,4  -> 1,2,3,4
 *   1-4      -> 1,2,3,4
 *   1-4:2    -> 1,3
 *   2-3,8-9  -> 2,3,8,9
 */
class CpuList {
public:
    /**
     * Parse a list of CPUs from a comma-separated string.
     *
     * @param list string representing a list of CPU numbers separated by commas.
     */
    CpuList(const std::string& list = "");

    /**
     * Get the CPU affinity for index \a index (1-based).
     */
    std::string CpuAtIndex(int index) const;

    bool IsValid() { return is_valid; }

    /**
     * Access to the parsed CPUs.
     */
    const std::vector<int>& Indices() const { return cpus; }

    /**
     * @return CPU indices as string sorted and joined using by \a sep.
     */
    std::string IndicesSetString(const std::string& sep = ",") const;

private:
    bool is_valid = true;
    std::vector<int> cpus;
};


} // namespace zeek::detail
