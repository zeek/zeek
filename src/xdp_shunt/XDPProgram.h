// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/IntrusivePtr.h"
#include "zeek/OpaqueVal.h"

#include "bpf/UserXDP.h"

namespace zeek::plugin::detail::Zeek_XDP_Shunter {

extern zeek::OpaqueTypePtr program_opaque;

class XDPProgramVal : public zeek::OpaqueVal {
public:
    XDPProgramVal() : zeek::OpaqueVal(program_opaque) {}
    XDPProgramVal(struct filter* prog, xdp_options opts)
        : OpaqueVal(program_opaque), prog(prog), opts(opts), is_set(true) {}
    XDPProgramVal(struct filter* prog) : OpaqueVal(program_opaque), prog(prog), is_set(true) {}

    ~XDPProgramVal() override = default;

    static zeek::expected<XDPProgramVal*, std::string> CastFromAny(Val* prog) {
        if ( prog->GetType() != program_opaque )
            return zeek::unexpected<std::string>("Invalid XDP program");

        auto xdp_prog = dynamic_cast<XDPProgramVal*>(prog);
        if ( ! xdp_prog )
            return zeek::unexpected<std::string>("Invalid XDP program");

        return xdp_prog;
    }

    struct filter* prog = nullptr;
    // Needed for detaching at the end if Zeek loaded the XDP program.
    xdp_options opts = {};
    bool is_set = false;

protected:
    zeek::IntrusivePtr<Val> DoClone(CloneState* state) override { return {zeek::NewRef{}, this}; }

    DECLARE_OPAQUE_VALUE_DATA(XDPProgramVal)
};

} // namespace zeek::plugin::detail::Zeek_XDP_Shunter
