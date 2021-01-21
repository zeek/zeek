// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <time.h> // for time_t
#include <string>
#include <vector>
#include <list>
#include <map>

#include "zeek/zeekygen/Info.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/ID.h"
#include "zeek/util.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(TypeDecl, zeek);

namespace zeek::zeekygen::detail {

class ScriptInfo;

/**
 * Information regarding a script-level identifier and its documentation.
 */
class IdentifierInfo : public Info {

public:

	/**
	 * Create a new identifier info object.
	 * @param id The script-level identifier.
	 * @param script The info object associated with the script in which \a id
	 * is declared.
	 * @param from_redef  Whether the identifier was create as part of a
	 * redefinition (e.g. an enum).
	 */
	IdentifierInfo(zeek::detail::IDPtr id, ScriptInfo* script,
	               bool from_redef = false);

	/**
	 * Dtor.  Releases any references to script-level objects.
	 */
	~IdentifierInfo() override;

	/**
	 * Returns the initial value of the identifier.
	 */
	const ValPtr& InitialVal() const
		{ return initial_val; }

	/**
	 * Add a comment associated with the identifier.  If the identifier is a
	 * record type and it's in the middle of parsing fields, the comment is
	 * associated with the last field that was parsed.
	 * @param comment A string extracted from Zeekygen-style comment.
	 */
	void AddComment(const std::string& comment)
		{ last_field_seen ? last_field_seen->comments.push_back(comment)
		                  : comments.push_back(comment); }

	/**
	 * Associate several comments with the identifier.  They will be appended
	 * to the end of the list of any current comments.
	 * @param cmtns A vector of comments to associate.
	 */
	void AddComments(const std::vector<std::string>& cmtns)
		{ comments.insert(comments.end(), cmtns.begin(), cmtns.end()); }

	/**
	 * Register a redefinition of the identifier.
	 * @param from_script The script in which the redef occurred.
	 * @param ic The initialization class used (e.g. =, +=, -=)
	 * @param init_expr The initialization expression used.
	 * @param comments Comments associated with the redef statement.
	 */
	void AddRedef(const std::string& from_script, zeek::detail::InitClass ic,
	              zeek::detail::ExprPtr init_expr,
	              const std::vector<std::string>& comments);

	/**
	 * Register a record field associated with the identifier
	 * (which is implicitly a record type).
	 * @param field The name/type information of the field.
	 * @param script The script in which the field was declared.  This may
	 * differ from the script in which a record type is declared due to redefs.
	 * @param comments Comments associated with the record field.
	 * @param from_redef  The field is from a record redefinition.
	 */
	void AddRecordField(const TypeDecl* field, const std::string& script,
	                    std::vector<std::string>& comments, bool from_redef);

	/**
	 * Signals that a record type has been completely parsed.  This resets
	 * internal tracking of the last record field seen so that "##<"-style
	 * comments are correctly associated.
	 */
	void CompletedTypeDecl()
		{ last_field_seen = nullptr; }

	/**
	 * @return the script-level ID tracked by this info object.
	 */
	zeek::detail::ID* GetID() const
		{ return id.get(); }

	/**
	 * @return The script which declared the script-level identifier.
	 */
	ScriptInfo* GetDeclaringScript() const
	    { return declaring_script; }

	/**
	 * @param field A record field name.
	 * @return The script which declared the record field name.
	 */
	std::string GetDeclaringScriptForField(const std::string& field) const;

	/**
	 * @return True if the identifier was created as part of a redefinition
	 * (e.g. an enum).
	 */
	bool IsFromRedef() const
		{ return from_redef; }

	/**
	 * @param field A record field name.
	 * @return True if the field name was added to a record as part of a redef.
	 */
	bool FieldIsFromRedef(const std::string& field) const;

	/**
	 * @return All Zeekygen comments associated with the identifier.
	 */
	std::vector<std::string> GetComments() const;

	/**
	 * @param field A record field name.
	 * @return All Zeekygen comments associated with the record field.
	 */
	std::vector<std::string> GetFieldComments(const std::string& field) const;

	/**
	 * Tracks useful information related to a redef.
	 */
	struct Redefinition {
		std::string from_script; /**< Name of script doing the redef. */
		zeek::detail::InitClass ic;
		zeek::detail::ExprPtr init_expr;
		std::vector<std::string> comments; /**< Zeekygen comments on redef. */

		Redefinition(std::string arg_script, zeek::detail::InitClass arg_ic,
		             zeek::detail::ExprPtr arg_expr,
		             std::vector<std::string> arg_comments);

		~Redefinition();
	};

	/**
	 * Get a list of information about redefinitions of the identifier within
	 * a particular script.
	 * @param from_script The name of a script in which to look for redefs.
	 * @return A list of redefs that occurred in \a from_script.
	 */
	std::list<Redefinition> GetRedefs(const std::string& from_script) const;

	/**
	 * Get a list of information about redefinitions of the identifier.
	 * @return A list of redefs that occurred for the identifier.
	 */
	const std::list<Redefinition*>& GetRedefs() const
		{ return redefs; }

private:

	time_t DoGetModificationTime() const override;

	std::string DoName() const override
		{ return id->Name(); }

	std::string DoReStructuredText(bool roles_only) const override;

	struct RecordField {
		~RecordField();

		TypeDecl* field;
		std::string from_script;
		std::vector<std::string> comments;
		bool from_redef;
	};

	typedef std::list<Redefinition*> redef_list;
	typedef std::map<std::string, RecordField*> record_field_map;

	std::vector<std::string> comments;
	zeek::detail::IDPtr id;
	ValPtr initial_val;
	redef_list redefs;
	record_field_map fields;
	RecordField* last_field_seen;
	ScriptInfo* declaring_script;
	bool from_redef = false;
};

} // namespace zeek::zeekygen::detail
