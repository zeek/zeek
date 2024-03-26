#include "Utils.h"

#include "zeek/ID.h"
#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/telemetry/telemetry.bif.h"
#include "zeek/util.h"

using namespace zeek;

namespace zeek::telemetry::detail {

std::string BuildFullPrometheusName(std::string_view prefix, std::string_view name, std::string_view unit,
                                    bool is_sum) {
    if ( prefix.empty() || name.empty() )
        reporter->FatalError("Telemetry metric families must have a non-zero-length prefix and name");

    std::string fn = util::fmt("%s_%s", prefix.data(), name.data());
    std::for_each(fn.begin(), fn.end(), [](char& c) {
        if ( ! std::isalnum(c) )
            c = '_';
    });

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
