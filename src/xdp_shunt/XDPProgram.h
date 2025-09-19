#include <zeek/IntrusivePtr.h>
#include <zeek/OpaqueVal.h>

#include "bpf/UserXDP.h"

namespace xdp::shunter::detail {

extern zeek::OpaqueTypePtr program_opaque;

class XDPProgramVal : public zeek::OpaqueVal {
public:
    XDPProgramVal() : zeek::OpaqueVal(detail::program_opaque) {}
    XDPProgramVal(struct filter* prog) : OpaqueVal(detail::program_opaque), prog(std::move(prog)) {}
    ~XDPProgramVal() override = default;

    static xdp::shunter::detail::XDPProgramVal* CastFromAny(Val* prog) {
        // TODO
        if ( prog->GetType() != detail::program_opaque )
            ;
        return dynamic_cast<xdp::shunter::detail::XDPProgramVal*>(prog);
    }

    struct filter* prog;

protected:
    zeek::IntrusivePtr<Val> DoClone(CloneState* state) override { return {zeek::NewRef{}, this}; }

    DECLARE_OPAQUE_VALUE_DATA(XDPProgramVal)
};
using XDPProgramPtr = zeek::IntrusivePtr<struct xdp_program>;

} // namespace xdp::shunter::detail
