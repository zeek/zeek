// See the file "COPYING" in the main distribution directory for copyright.

#include "utils.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <algorithm>
#include <charconv>
#include <set>
#include <string>

namespace zeek::detail {

void ltrim(std::string& s) {
    s.erase(s.begin(), std::ranges::find_if(s.begin(), s.end(), [](unsigned char ch) { return ! std::isspace(ch); }));
}

void rtrim(std::string& s) {
    s.erase(std::ranges::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return ! std::isspace(ch); }).base(),
            s.end());
}

void trim(std::string& s) {
    ltrim(s);
    rtrim(s);
}

void tolower(std::string& s) {
    std::ranges::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
}

std::optional<int> parse_int(std::string_view sv) {
    if ( sv.size() == 0 )
        return {};

    int result;
    auto r = std::from_chars<int>(sv.data(), sv.data() + sv.size(), result);
    if ( r.ec == std::errc::invalid_argument || r.ec == std::errc::result_out_of_range )
        return {};

    if ( r.ptr != sv.end() )
        return {};

    return result;
}


// Split \a v by \a delim into a vector of string views.
std::vector<std::string_view> split(std::string_view v, char delim) {
    std::vector<std::string_view> result;
    size_t pos = 0;

    do {
        size_t end = v.find(delim, pos);
        // if npos, npos-pos still means till end of string.
        result.emplace_back(v.substr(pos, end - pos));
        if ( end == std::string_view::npos )
            break;

        pos = end + 1;

        // Trailing delimiter? Add empty entry.
        if ( pos >= v.size() )
            result.emplace_back(v.substr(pos, 0));
    } while ( pos < v.size() );

    return result;
}

// " ".join(...) in C++, meh.
std::string join(std::span<const std::string> args, const std::string& sep) {
    std::string result;

    for ( const auto& arg : args ) {
        if ( ! result.empty() && ! sep.empty() && ! arg.empty() )
            result += sep;

        result += arg;
    }

    return result;
}

std::string join(std::span<const std::filesystem::path> paths, const std::string& sep) {
    std::vector<std::string> args;
    args.reserve(paths.size());
    for ( const auto& p : paths )
        args.emplace_back(p.string());
    return join(args, sep);
}

std::optional<std::string> substitute_vars(const std::string& s, const std::map<std::string, std::string>& vars) {
    std::size_t pos = 0;
    std::string result;

    while ( pos < s.size() ) {
        std::size_t needle = s.find("${", pos);
        if ( needle == std::string::npos ) {
            result += s.substr(pos);
            break;
        }
        // std::fprintf(stderr, "found needle at %zu in %s\n", needle, s.c_str());

        // Check for escaped $, don't include the \\, but include the ${
        if ( needle > 0 && s[needle - 1] == '\\' ) {
            result += s.substr(pos, needle - (pos + 1));
            result += "${";
            pos = needle + 2;
            continue;
        }

        if ( needle > pos )
            result += s.substr(pos, needle - pos);

        // Skip the ${
        pos = needle + 2;

        std::size_t close_needle = s.find('}', pos);

        // Missing closing } - it's an error.
        if ( close_needle == std::string::npos )
            return std::nullopt;

        std::string var = s.substr(pos, close_needle - pos);
        auto it = vars.find(var);

        if ( it == vars.end() ) {
            fprintf(stderr, "invalid substitution var '%s'\n", var.c_str());
            return std::nullopt;
        }

        result += it->second;

        pos = close_needle + 1;
    }

    return result;
}

bool is_valid_ip(const std::string& s) {
    // 1.2.3.4 or [::1]
    if ( s.size() < 5 )
        return false;

    unsigned char buf[sizeof(struct in6_addr)];

    if ( s[0] == '[' and s[s.size() - 1] == ']' ) {
        std::string stripped = std::string(s.substr(1, s.size() - 2));
        return inet_pton(AF_INET6, stripped.c_str(), buf) == 1;
    }

    return inet_pton(AF_INET, s.c_str(), buf) == 1;
}

CpuList::CpuList(const std::string& list) {
    // Split gives us a single empty entry for an empty list,
    // just handle that here upfront.
    if ( list.empty() ) {
        is_valid = true;
        return;
    }

    auto number_or_range_parts = split(list, ',');

    for ( const auto& number_or_range : number_or_range_parts ) {
        auto parts = split(number_or_range, '-');

        if ( parts.size() == 2 ) {
            // Parse the l-r[:stride] format.
            int stride = 1;
            std::optional<int> l, r;

            // Any stride in the range?
            auto stride_parts = split(parts[1], ':');
            if ( stride_parts.size() == 2 ) {
                auto maybe_stride = parse_int(stride_parts[1]);
                if ( maybe_stride.has_value() && *maybe_stride > 0 ) {
                    stride = *maybe_stride;
                }
                else {
                    is_valid = false;
                    return;
                }

                r = parse_int(stride_parts[0]);
            }
            else if ( stride_parts.size() == 1 ) {
                r = parse_int(parts[1]);
            }
            else {
                is_valid = false;
                return;
            }

            l = parse_int(parts[0]);

            if ( ! l.has_value() || ! r.has_value() || *l < 0 || *r < 0 || *r < *l ) {
                is_valid = false;
                return;
            }

            // Expand range with strides.
            for ( int i = *l; i <= *r; i += stride )
                cpus.push_back(i);
        }
        else if ( parts.size() == 1 ) {
            // Not a range, just a single number expected.
            auto n = parse_int(parts[0]);
            if ( ! n ) {
                is_valid = false;
                return;
            }
            cpus.push_back(*n);
        }
        else {
            is_valid = list.empty(); // no parts and empty input: valid.
            return;
        }
    }
}

std::string CpuList::CpuAtIndex(int index) const {
    if ( index <= 0 )
        throw std::logic_error("bad index: " + std::to_string(index));

    if ( cpus.empty() )
        return "";

    return std::to_string(cpus[(index - 1) % cpus.size()]);
}

std::string CpuList::IndicesSetString(const std::string& sep) const {
    std::set<int> cpus_set{cpus.begin(), cpus.end()};
    std::vector cpus_vec(cpus_set.begin(), cpus_set.end());
    std::sort(cpus_vec.begin(), cpus_vec.end());
    std::vector<std::string> cpus_str_vec;
    cpus_str_vec.reserve(cpus_vec.size());
    for ( auto i : cpus_vec )
        cpus_str_vec.emplace_back(std::to_string(i));

    return join(cpus_str_vec, sep);
}

} // namespace zeek::detail
