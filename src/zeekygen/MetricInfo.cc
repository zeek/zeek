// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeekygen/MetricInfo.h"

#include "zeek/Desc.h"

namespace zeek::zeekygen::detail {


MetricInfo::MetricInfo(std::string name, std::string type, std::vector<std::string> labels, std::string unit,
                       std::string helptext)
    : name(std::move(name)),
      type(std::move(type)),
      labels(std::move(labels)),
      unit(std::move(unit)),
      helptext(std::move(helptext)) {}

std::string MetricInfo::DoReStructuredText(bool roles_only) const {
    ODesc d;
    d.SetQuotes(true);
    d.SetIndentSpaces(3);

    d.Add(".. zeek:metric:: ");
    d.Add(name);
    d.NL();
    d.PushIndent();

    d.Add(":Type: ");
    d.Add(type.c_str());
    d.NL();
    d.Add(":Labels:");
    for ( const auto& l : labels ) {
        d.SP();
        d.Add(l.c_str());
    }

    d.NL();
    d.NL();
    d.Add(helptext.c_str());

    return d.Description();
}

} // namespace zeek::zeekygen::detail
