// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <map>
#include <string>
#include <variant>

#include "zeek/Val.h"

#include "opentelemetry/sdk/metrics/observer_result.h"

namespace zeek::telemetry {
// Convert an int64_t or double to a DoubleValPtr. int64_t is casted.
template<typename T>
zeek::IntrusivePtr<zeek::DoubleVal> as_double_val(T val) {
    if constexpr ( std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t> ) {
        return zeek::make_intrusive<zeek::DoubleVal>(static_cast<double>(val));
    }
    else {
        static_assert(std::is_same_v<T, double>);
        return zeek::make_intrusive<zeek::DoubleVal>(val);
    }
};

template<typename T>
void build_observation(const std::map<std::pair<std::string, std::string>, T>& values,
                       opentelemetry::metrics::ObserverResult& result) {
    if ( opentelemetry::nostd::holds_alternative<
             opentelemetry::nostd::shared_ptr<opentelemetry::metrics::ObserverResultT<T>>>(result) ) {
        auto res =
            opentelemetry::nostd::get<opentelemetry::nostd::shared_ptr<opentelemetry::metrics::ObserverResultT<T>>>(
                result);

        for ( const auto& [k, v] : values ) {
            res->Observe(v, {k});
        }
    }
}

} // namespace zeek::telemetry
