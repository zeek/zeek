// See the file "COPYING" in the main distribution directory for copyright.

#include "pac_analyzer.h"

#include "pac_action.h"
#include "pac_context.h"
#include "pac_embedded.h"
#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_flow.h"
#include "pac_func.h"
#include "pac_output.h"
#include "pac_param.h"
#include "pac_paramtype.h"
#include "pac_state.h"
#include "pac_type.h"
#include "pac_varfield.h"

AnalyzerDecl::AnalyzerDecl(ID* id, DeclType decl_type, ParamList* params) : TypeDecl(id, params, new DummyType()) {
    decl_type_ = decl_type;

    statevars_ = new StateVarList();
    actions_ = new AnalyzerActionList();
    helpers_ = new AnalyzerHelperList();
    functions_ = new FunctionList();

    constructor_helpers_ = new AnalyzerHelperList();
    destructor_helpers_ = new AnalyzerHelperList();
    eof_helpers_ = new AnalyzerHelperList();

    SetAnalyzerContext();

    env_ = nullptr;
}

AnalyzerDecl::~AnalyzerDecl() {
    delete_list(statevars_);
    delete_list(actions_);
    delete_list(helpers_);
    delete_list(functions_);
    delete_list(params_);
    delete_list(constructor_helpers_);
    delete_list(destructor_helpers_);
    delete_list(eof_helpers_);
}

void AnalyzerDecl::AddElements(AnalyzerElementList* elemlist) {
    ASSERT(! env_);
    if ( elemlist )
        for ( const auto& elem : *elemlist ) {
            switch ( elem->type() ) {
                case AnalyzerElement::STATE: {
                    ASSERT(0);
                    AnalyzerState* state_elem = (AnalyzerState*)elem;
                    statevars_->insert(statevars_->end(), state_elem->statevars()->begin(),
                                       state_elem->statevars()->end());
                } break;
                case AnalyzerElement::ACTION: {
                    ASSERT(0);
                    AnalyzerAction* action_elem = (AnalyzerAction*)elem;
                    actions_->push_back(action_elem);
                } break;
                case AnalyzerElement::HELPER: {
                    AnalyzerHelper* helper_elem = (AnalyzerHelper*)elem;

                    switch ( helper_elem->helper_type() ) {
                        case AnalyzerHelper::INIT_CODE: constructor_helpers_->push_back(helper_elem); break;
                        case AnalyzerHelper::CLEANUP_CODE: destructor_helpers_->push_back(helper_elem); break;
                        case AnalyzerHelper::EOF_CODE: eof_helpers_->push_back(helper_elem); break;
                        default: helpers_->push_back(helper_elem);
                    }
                } break;
                case AnalyzerElement::FUNCTION: {
                    AnalyzerFunction* func_elem = (AnalyzerFunction*)elem;
                    Function* func = func_elem->function();
                    func->set_analyzer_decl(this);
                    functions_->push_back(func);
                } break;
                case AnalyzerElement::FLOW: {
                    AnalyzerFlow* flow_elem = (AnalyzerFlow*)elem;
                    ProcessFlowElement(flow_elem);
                } break;
                case AnalyzerElement::DATAUNIT: {
                    AnalyzerDataUnit* dataunit_elem = (AnalyzerDataUnit*)elem;
                    ProcessDataUnitElement(dataunit_elem);
                } break;
            }
        }
}

string AnalyzerDecl::class_name() const { return id_->Name(); }

void AnalyzerDecl::Prepare() {
    TypeDecl::Prepare();

    ASSERT(statevars_->empty());
    ASSERT(actions_->empty());

    if ( functions_ )
        for ( const auto& function : *functions_ )
            function->Prepare(env_);

    if ( statevars_ )
        for ( const auto& statevar : *statevars_ )
            env_->AddID(statevar->id(), STATE_VAR, statevar->type());

    if ( actions_ )
        for ( const auto& action : *actions_ )
            action->InstallHook(this);
}

void AnalyzerDecl::GenForwardDeclaration(Output* out_h) {
    out_h->println("class %s;", class_name().c_str());
    if ( functions_ )
        for ( const auto& function : *functions_ )
            function->GenForwardDeclaration(out_h);
}

void AnalyzerDecl::GenActions(Output* out_h, Output* out_cc) {
    if ( actions_ )
        for ( const auto& action : *actions_ )
            action->GenCode(out_h, out_cc, this);
}

void AnalyzerDecl::GenHelpers(Output* out_h, Output* out_cc) {
    if ( helpers_ )
        for ( const auto& helper : *helpers_ )
            helper->GenCode(out_h, out_cc, this);
}

void AnalyzerDecl::GenPubDecls(Output* out_h, Output* out_cc) {
    TypeDecl::GenPubDecls(out_h, out_cc);

    GenProcessFunc(out_h, out_cc);
    GenGapFunc(out_h, out_cc);
    GenEOFFunc(out_h, out_cc);
    out_h->println("");

    if ( ! functions_->empty() ) {
        out_h->println("// Functions");
        GenFunctions(out_h, out_cc);
        out_h->println("");
    }

    // TODO: export public state variables
}

void AnalyzerDecl::GenPrivDecls(Output* out_h, Output* out_cc) {
    TypeDecl::GenPrivDecls(out_h, out_cc);

    if ( ! helpers_->empty() ) {
        out_h->println("");
        out_h->println("// Additional members");
        GenHelpers(out_h, out_cc);
    }

    // TODO: declare state variables
}

void AnalyzerDecl::GenInitCode(Output* out_cc) {
    TypeDecl::GenInitCode(out_cc);
    if ( constructor_helpers_ )
        for ( const auto& helper : *constructor_helpers_ )
            helper->GenCode(nullptr, out_cc, this);
}

void AnalyzerDecl::GenCleanUpCode(Output* out_cc) {
    TypeDecl::GenCleanUpCode(out_cc);
    if ( destructor_helpers_ )
        for ( const auto& helper : *destructor_helpers_ )
            helper->GenCode(nullptr, out_cc, this);
}

void AnalyzerDecl::GenStateVarDecls(Output* out_h) {
    if ( statevars_ )
        for ( const auto& var : *statevars_ )
            var->GenDecl(out_h, env_);
}

void AnalyzerDecl::GenStateVarSetFunctions(Output* out_h) {
    if ( statevars_ )
        for ( const auto& var : *statevars_ )
            var->GenSetFunction(out_h, env_);
}

void AnalyzerDecl::GenStateVarInitCode(Output* out_cc) {
    if ( statevars_ )
        for ( const auto& var : *statevars_ )
            var->GenInitCode(out_cc, env_);
}

void AnalyzerDecl::GenStateVarCleanUpCode(Output* out_cc) {
    if ( statevars_ )
        for ( const auto& var : *statevars_ )
            var->GenCleanUpCode(out_cc, env_);
}

void AnalyzerDecl::GenFunctions(Output* out_h, Output* out_cc) {
    if ( functions_ )
        for ( const auto& function : *functions_ )
            function->GenCode(out_h, out_cc);
}

AnalyzerState::~AnalyzerState() {
    // Note: do not delete elements of statevars_, because they
    // are referenced by the AnalyzerDecl.
    delete statevars_;
}

AnalyzerHelper::~AnalyzerHelper() { delete code_; }

void AnalyzerHelper::GenCode(Output* out_h, Output* out_cc, AnalyzerDecl* decl) {
    Output* out = nullptr;
    switch ( helper_type_ ) {
        case MEMBER_DECLS: out = out_h; break;
        case INIT_CODE:
        case CLEANUP_CODE:
        case EOF_CODE: out = out_cc; break;
    }
    ASSERT(out);
    code()->GenCode(out, decl->env());
}

FlowField::FlowField(ID* flow_id, ParameterizedType* flow_type)
    : Field(FLOW_FIELD, TYPE_NOT_TO_BE_PARSED | CLASS_MEMBER | PUBLIC_READABLE, flow_id, flow_type) {}

void FlowField::GenInitCode(Output* out_cc, Env* env) { type_->GenPreParsing(out_cc, env); }

AnalyzerFlow::AnalyzerFlow(Direction dir, ID* type_id, ExprList* params)
    : AnalyzerElement(FLOW), dir_(dir), type_id_(type_id) {
    if ( ! params )
        params = new ExprList();

    // Add "this" to the list of params
    params->insert(params->begin(), new Expr(this_id->clone()));

    ID* flow_id = ((dir == UP) ? upflow_id : downflow_id)->clone();

    ParameterizedType* flow_type = new ParameterizedType(type_id_, params);

    flow_field_ = new FlowField(flow_id, flow_type);

    flow_decl_ = nullptr;
}

AnalyzerFlow::~AnalyzerFlow() { delete flow_field_; }

FlowDecl* AnalyzerFlow::flow_decl() {
    DEBUG_MSG("Getting flow_decl for %s\n", type_id_->Name());
    if ( ! flow_decl_ ) {
        Decl* decl = Decl::LookUpDecl(type_id_);
        if ( decl && decl->decl_type() == Decl::FLOW )
            flow_decl_ = static_cast<FlowDecl*>(decl);
        if ( ! flow_decl_ ) {
            throw Exception(this, "cannot find the flow declaration");
        }
    }
    return flow_decl_;
}
