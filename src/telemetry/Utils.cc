// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Utils.h"

#include "zeek/ID.h"
#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/util.h"

using namespace zeek;

namespace zeek::telemetry::detail {

std::string BuildFullPrometheusName(std::string_view prefix, std::string_view name, std::string_view unit,
                                    bool is_sum) {
    if ( prefix.empty() || name.empty() )
        reporter->FatalError("Telemetry metric families must have a non-zero-length prefix and name");

    std::string fn = util::fmt("%.*s_%.*s", static_cast<int>(prefix.size()), prefix.data(),
                               static_cast<int>(name.size()), name.data());
    std::for_each(fn.begin(), fn.end(), [](char& c) {
        if ( ! std::isalnum(c) )
            c = '_';
    });

    // Suffixes of full metric names of _total are reserved by Prometheus. Disallow their use here.
    if ( util::ends_with(fn, "_total") )
        reporter->FatalError("Metric names cannot end with '_total'");
    else if ( unit == "total" || util::ends_with(unit, "_total") )
        reporter->FatalError("Metric units cannot end with '_total'");

    // We were previously using "1" to mean "no unit value" for whatever reason, so we have to handle that now
    // to mean the same thing.
    if ( ! unit.empty() && unit != "1" )
        fn.append("_").append(unit);

    if ( is_sum )
        fn.append("_total");

    return fn;
}

prometheus::Labels BuildPrometheusLabels(Span<const LabelView> labels) {
    prometheus::Labels p_labels;

    bool found_endpoint = false;
    for ( const auto& lbl : labels ) {
        p_labels.emplace(util::strreplace(std::string{lbl.first}, "-", "_"), lbl.second);
        if ( lbl.first == "endpoint" )
            found_endpoint = true;
    }

    if ( ! found_endpoint ) {
        auto endpoint = id::find_val("Telemetry::metrics_endpoint_name")->AsStringVal();
        if ( endpoint && endpoint->Len() > 0 )
            p_labels.emplace("endpoint", endpoint->ToStdString());
    }

    return p_labels;
}

} // namespace zeek::telemetry::detail
