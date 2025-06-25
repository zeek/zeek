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

    static std::string metrics_endpoint_label =
        id::find_val<zeek::StringVal>("Telemetry::metrics_endpoint_label")->ToStdString();

    static std::string metrics_endpoint_name =
        id::find_val<zeek::StringVal>("Telemetry::metrics_endpoint_name")->ToStdString();

    bool found_endpoint_label = false;
    for ( const auto& lbl : labels ) {
        p_labels.emplace(util::strreplace(std::string{lbl.first}, "-", "_"), lbl.second);
        if ( lbl.first == metrics_endpoint_label )
            found_endpoint_label = true;
    }

    if ( ! found_endpoint_label && ! metrics_endpoint_label.empty() && ! metrics_endpoint_name.empty() )
        p_labels.emplace(metrics_endpoint_label, metrics_endpoint_name);

    return p_labels;
}

} // namespace zeek::telemetry::detail
