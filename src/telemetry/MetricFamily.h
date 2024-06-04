// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <vector>

#include "zeek/Span.h"
#include "zeek/util.h"

namespace zeek::telemetry {

/**
 * Manages a collection (family) of metrics. All members of the family share
 * the same prefix (namespace), name, and label dimensions.
 */
class MetricFamily {
public:
    virtual ~MetricFamily() = default;

    virtual zeek_int_t MetricType() const = 0;

    std::vector<std::string> LabelNames() const { return label_names; }

protected:
    MetricFamily(Span<const std::string_view> labels) {
        for ( const auto& lbl : labels )
            label_names.emplace_back(lbl);
    }

    std::vector<std::string> label_names;
};

} // namespace zeek::telemetry
