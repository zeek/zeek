#ifndef pac_redef_h
#define pac_redef_h

#include "pac_decl.h"

Decl *ProcessCaseTypeRedef(const ID *id, CaseFieldList *casefieldlist);
Decl *ProcessCaseExprRedef(const ID *id, CaseExprList *caseexprlist);
Decl *ProcessAnalyzerRedef(const ID *id, 
			Decl::DeclType decl_type, 
			AnalyzerElementList *elements);
Decl *ProcessTypeAttrRedef(const ID *id, AttrList *attrlist);

#endif  // pac_redef_h
