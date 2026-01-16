// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/iosource/Component.h"

#include "zeek/Desc.h"
#include "zeek/Reporter.h"
#include "zeek/Type.h"

namespace zeek::iosource {

Component::Component(const std::string& name) : plugin::Component(plugin::component::IOSOURCE, name) {}

Component::Component(plugin::component::Type type, const std::string& name) : plugin::Component(type, name) {}

PktSrcComponent::PktSrcComponent(const std::string& arg_name, const std::string& arg_prefix, InputType arg_type,
                                 factory_callback arg_factory, std::vector<uint32_t> arg_magic_nums)
    : Component(plugin::component::PKTSRC, arg_name),
      type(arg_type),
      factory(arg_factory),
      magic_nums(std::move(arg_magic_nums)) {
    util::tokenize_string(arg_prefix, ":", &prefixes);
}

const std::vector<std::string>& PktSrcComponent::Prefixes() const { return prefixes; }

bool PktSrcComponent::HandlesPrefix(const std::string& prefix) const {
    return std::ranges::find(prefixes, prefix) != prefixes.end();
}

bool PktSrcComponent::HandlesMagicNumber(uint32_t magic_num) const {
    return std::ranges::find(magic_nums, magic_num) != magic_nums.end();
}

bool PktSrcComponent::DoesLive() const { return type == LIVE || type == BOTH; }

bool PktSrcComponent::DoesTrace() const { return type == TRACE || type == BOTH; }

PktSrcComponent::factory_callback PktSrcComponent::Factory() const { return factory; }

void PktSrcComponent::DoDescribe(ODesc* d) const {
    Component::DoDescribe(d);

    std::string prefs;

    for ( const auto& pfx : prefixes ) {
        if ( ! prefs.empty() )
            prefs += ", ";

        prefs += '"' + pfx + '"';
    }

    d->Add("interface prefix");
    if ( prefixes.size() > 1 )
        d->Add("es");

    d->Add(" ");
    d->Add(prefs);

    if ( ! magic_nums.empty() ) {
        d->Add("; magic number");
        if ( magic_nums.size() > 1 )
            d->Add("s");

        d->Add(" ");
        for ( auto it = magic_nums.begin(); it != magic_nums.end(); ++it ) {
            if ( it != magic_nums.begin() )
                d->Add(", ");
            d->Add(util::fmt("0x%08x", *it));
        }
    }

    d->Add("; supports ");

    switch ( type ) {
        case LIVE: d->Add("live input"); break;

        case TRACE: d->Add("trace input"); break;

        case BOTH: d->Add("live and trace input"); break;

        default: reporter->InternalError("unknown PkrSrc type");
    }
}

PktDumperComponent::PktDumperComponent(const std::string& name, const std::string& arg_prefix,
                                       factory_callback arg_factory)
    : plugin::Component(plugin::component::PKTDUMPER, name) {
    util::tokenize_string(arg_prefix, ":", &prefixes);
    factory = arg_factory;
}

PktDumperComponent::factory_callback PktDumperComponent::Factory() const { return factory; }

const std::vector<std::string>& PktDumperComponent::Prefixes() const { return prefixes; }

bool PktDumperComponent::HandlesPrefix(const std::string& prefix) const {
    for ( const auto& pfx : prefixes ) {
        if ( pfx == prefix )
            return true;
    }

    return false;
}

void PktDumperComponent::DoDescribe(ODesc* d) const {
    plugin::Component::DoDescribe(d);

    std::string prefs;

    for ( const auto& pfx : prefixes ) {
        if ( ! prefs.empty() )
            prefs += ", ";

        prefs += '"' + pfx + '"';
    }

    d->Add("dumper prefix");

    if ( prefixes.size() > 1 )
        d->Add("es");

    d->Add(": ");
    d->Add(prefs);
}

} // namespace zeek::iosource
