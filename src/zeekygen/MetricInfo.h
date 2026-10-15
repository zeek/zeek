// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <ctime> // for time_t
#include <string>
#include <vector>

#include "zeek/zeekygen/Info.h"

namespace zeek::zeekygen::detail {

/**
 * Information about Zeek metric.
 */
class MetricInfo : public Info {
public:
    MetricInfo(std::string name, std::string type, std::vector<std::string> labels, std::string unit,
               std::string helptext);

private:
    std::string DoName() const override { return name; }

    std::string DoReStructuredText(bool roles_only) const override;

    time_t DoGetModificationTime() const override { return 0; }

    std::string name;
    std::string type;
    std::vector<std::string> labels;
    std::string unit;
    std::string helptext;
};

} // namespace zeek::zeekygen::detail
