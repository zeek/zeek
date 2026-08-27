// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeekygen/IdentifierReST.h"

#include <cassert>
#include <string>

#include "zeek/Attr.h"
#include "zeek/Desc.h"
#include "zeek/Dict.h"
#include "zeek/Expr.h"
#include "zeek/ID.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/util.h"
#include "zeek/zeekygen/IdentifierInfo.h"
#include "zeek/zeekygen/Manager.h"
#include "zeek/zeekygen/utils.h"

namespace zeek::zeekygen::detail {

void describe_id_rest_short(const zeek::detail::ID* id, ODesc* d) {
    const auto& type = id->GetType();

    if ( id->IsType() )
        d->Add(":zeek:type:`");
    else
        d->Add(":zeek:id:`");

    d->Add(id->Name());
    d->Add("`");

    if ( type ) {
        d->Add(": ");
        d->Add(":zeek:type:`");

        if ( ! id->IsType() && ! type->GetName().empty() )
            d->Add(type->GetName().c_str());
        else {
            TypeTag t = type->Tag();

            switch ( t ) {
                case TYPE_TABLE: d->Add(type->IsSet() ? "set" : type_name(t)); break;

                case TYPE_FUNC: d->Add(type->AsFuncType()->FlavorString().c_str()); break;

                case TYPE_ENUM:
                    if ( id->IsType() )
                        d->Add(type_name(t));
                    else
                        d->Add(zeek::detail::zeekygen_mgr->GetEnumTypeName(id->Name()).c_str());
                    break;

                default: d->Add(type_name(t)); break;
            }
        }

        d->Add("`");
    }

    if ( const auto& attrs = id->GetAttrs() ) {
        d->SP();
        attrs->DescribeReST(d, true);
    }
}

void describe_id_rest(const zeek::detail::ID* id, ODesc* d, bool roles_only) {
    const auto& type = id->GetType();

    if ( roles_only ) {
        if ( id->IsType() )
            d->Add(":zeek:type:`");
        else
            d->Add(":zeek:id:`");
        d->Add(id->Name());
        d->Add("`");
    }
    else {
        if ( id->IsType() )
            d->Add(".. zeek:type:: ");
        else
            d->Add(".. zeek:id:: ");

        d->Add(id->Name());

        if ( auto sc = source_code_range(id) ) {
            d->PushIndent();
            d->Add(util::fmt(":source-code: %s", sc->data()));
            d->PopIndentNoNL();
        }
    }

    d->PushIndent();
    d->NL();

    if ( type ) {
        d->Add(":Type: ");

        if ( ! id->IsType() && ! type->GetName().empty() ) {
            d->Add(":zeek:type:`");
            d->Add(type->GetName());
            d->Add("`");
        }
        else {
            type->DescribeReST(d, roles_only);

            if ( IsFunc(type->Tag()) ) {
                auto ft = type->AsFuncType();

                if ( ft->Flavor() == FUNC_FLAVOR_EVENT || ft->Flavor() == FUNC_FLAVOR_HOOK ) {
                    const auto& protos = ft->Prototypes();

                    if ( protos.size() > 1 ) {
                        auto first = true;

                        for ( const auto& proto : protos ) {
                            if ( first ) {
                                first = false;
                                continue;
                            }

                            d->NL();
                            d->Add(":Type: :zeek:type:`");
                            d->Add(ft->FlavorString());
                            d->Add("` (");
                            proto.args->DescribeFieldsReST(d, true);
                            d->Add(")");
                        }
                    }
                }
            }
        }

        d->NL();
    }

    if ( const auto& attrs = id->GetAttrs() ) {
        d->Add(":Attributes: ");
        attrs->DescribeReST(d);
        d->NL();
    }

    const auto& val = id->GetVal();

    if ( val && type && type->Tag() != TYPE_FUNC && type->InternalType() != TYPE_INTERNAL_VOID &&
         // Do not include a default value for enum const identifiers,
         // as their value can't be changed.
         ! id->IsEnumConst() &&

         // Values within Version module are likely to include a
         // constantly-changing version number and be a frequent
         // source of error/desynchronization, so don't include them.
         id->ModuleName() != "Version" ) {
        d->Add(":Default:");
        auto ii = zeek::detail::zeekygen_mgr->GetIdentifierInfo(id->Name());
        if ( ! ii )
            return;

        auto redefs = ii->GetRedefs();
        const auto& iv = ! redefs.empty() && ii->InitialVal() ? ii->InitialVal() : val;

        if ( type->InternalType() == TYPE_INTERNAL_OTHER ) {
            switch ( type->Tag() ) {
                case TYPE_TABLE:
                    if ( iv->AsTable()->Length() == 0 ) {
                        d->Add(" ``{}``");
                        d->NL();
                        break;
                    }
                    // Fall-through.

                default:
                    d->NL();
                    d->PushIndent();
                    d->Add("::");
                    d->NL();
                    d->PushIndent();
                    iv->DescribeReST(d);
                    d->PopIndent();
                    d->PopIndent();
            }
        }

        else {
            d->SP();
            iv->DescribeReST(d);
            d->NL();
        }

        for ( auto& ir : redefs ) {
            if ( ! ir->init_expr )
                continue;

            if ( ir->ic == zeek::detail::INIT_NONE )
                continue;

            std::string redef_str;
            ODesc expr_desc;
            // Quotes keep empty strings from describing to nothing, which would
            // leave the literal block below empty and thus invalid ReST.
            expr_desc.SetQuotes(true);
            if ( ir->init_expr->IsConst() ) {
                const auto* expr_val = ir->init_expr->ExprVal();

                // The value ends up inside a literal block below, so avoid
                // Val::DescribeReST() for anything it would decorate with
                // inline ReST markup (that markup would show up verbatim).
                if ( expr_val->GetType()->InternalType() == TYPE_INTERNAL_OTHER )
                    expr_val->DescribeReST(&expr_desc);
                else
                    expr_val->Describe(&expr_desc);
            }
            else if ( auto tag = ir->init_expr->Tag();
                      tag == zeek::detail::EXPR_SET_CONSTRUCTOR || tag == zeek::detail::EXPR_TABLE_CONSTRUCTOR ) {
                // These constructors carry the identifier's own attributes, which
                // Expr::Describe() would append to the value. They're documented
                // separately under :Attributes:, so describe just the value here.
                expr_desc.Add(tag == zeek::detail::EXPR_SET_CONSTRUCTOR ? "set(" : "table(");
                ir->init_expr->GetOp1()->Describe(&expr_desc);
                expr_desc.Add(")");
            }
            else {
                ir->init_expr->Describe(&expr_desc);
            }

            redef_str = expr_desc.Description();
            redef_str = util::strreplace(redef_str, "\n", " ");

            d->Add(":Redefinition: ");
            d->Add(util::fmt("from :doc:`/scripts/%s`", ir->from_script.data()));
            d->NL();
            d->PushIndent();

            if ( ir->omit_value ) {
                d->Add("<< Value omitted due to ``@docs_omit_value`` annotation >>");
                d->NL();
            }
            else {
                if ( ir->ic == zeek::detail::INIT_FULL )
                    d->Add("``=``");
                else if ( ir->ic == zeek::detail::INIT_EXTRA )
                    d->Add("``+=``");
                else if ( ir->ic == zeek::detail::INIT_REMOVE )
                    d->Add("``-=``");
                else
                    assert(false);

                d->Add("::");
                d->NL();
                d->PushIndent();
                d->Add(redef_str.data());
                d->PopIndent();
                d->PopIndent();
            }
        }
    }
}

} // namespace zeek::zeekygen::detail
