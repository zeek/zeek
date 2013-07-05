#ifndef brodocobj_h
#define brodocobj_h

#include <cstdio>
#include <string>
#include <list>
#include <map>

#include "ID.h"

/**
 * This class wraps a Bro script identifier, providing methods relevant
 * to automatic generation of reStructuredText (reST) documentation for it.
 */
class BroDocObj {
public:
	/**
	 * BroDocObj constructor
	 * @param id a pointer to an identifier that is to be documented
	 * @param reST a reference to a pointer of a list of strings that
	 *        represent the reST documentation for the ID.  The pointer
	 *        will be set to 0 after this constructor finishes.
	 * @param is_fake whether the ID* is a dummy just for doc purposes
	 */
	BroDocObj(const ID* id, std::list<std::string>*& reST,
			bool is_fake = false);

	/**
	 * BroDocObj destructor
	 * Deallocates the memory associated with the list of reST strings
	 */
	~BroDocObj();

	/**
	 * Writes the reST representation of this object which includes
	 * 1) a reST friendly description of the ID
	 * 2) "##" or "##<" stylized comments.
	 *    Anything after these style of comments is inserted as-is into
	 *    the reST document.
	 * @param file The (already opened) file to write the reST to.
	 */
	void WriteReST(FILE* file) const;

	/**
	 * Writes a compact version of the ID and associated documentation
	 * for insertion into a table.
	 * @param file The (already opened) file to write the reST to.
	 * @param max_col The maximum length of the first table column
	 */
	void WriteReSTCompact(FILE* file, int max_col) const;

	/**
	 * @return the column size required by the reST representation of the ID
	 */
	int ColumnSize() const;

	/**
	 * Check whether this documentation is part of the public API.  In
	 * other words, this means that the identifier is declared as part of
	 * the global scope (has GLOBAL namespace or is exported from another
	 * namespace).
	 * @return true if the identifier is part of the script's public API
	 */
	bool IsPublicAPI() const;

	/**
	 * Return whether this object has documentation (## comments)
	 * @return true if the ID has comments associated with it
	 */
	bool HasDocumentation() const
		{
		return reST_doc_strings && reST_doc_strings->size() > 0;
		}

	/**
	 * @return whether this object will use reST role (T) or directive (F)
	 * notation for the wrapped identifier.  Roles are usually used
	 * for cross-referencing.
	 */
	bool UseRole() const	{ return use_role; }

	/**
	 * @param b whether this object will use reST role (T) or directive (F)
	 * notation for the wrapped identifier.  Roles are usually used
	 * for cross-referencing.
	 */
	void SetRole(bool b)	{ use_role = b; }

	/**
	 * Append any reST documentation strings in a given BroDocObj to this
	 * object's list and then delete the given BroDocObj
	 * @param o a pointer to a BroDocObj to subsume
	 */
	void Combine(const BroDocObj* o);

	/**
	 * @return the name of the wrapped identifier
	 */
	const char* Name() const	{ return broID->Name(); }

	/**
	 * @return the longest string element of the short description's list of
	 *         strings
	 */
	int LongestShortDescLen() const;

	/**
	 * Adds a reST documentation string to this BroDocObj's list.
	 * @param s the documentation string to append.
	 */
	void AddDocString(const std::string& s)
		{
		if ( ! reST_doc_strings )
			reST_doc_strings = new std::list<std::string>();
		reST_doc_strings->push_back(s);
		FormulateShortDesc();
		}

	static BroDocObj* last;

protected:
	std::list<std::string>* reST_doc_strings;
	std::list<std::string> short_desc;
	const ID* broID;
	bool is_fake_id; /**< Whether the ID* is a dummy just for doc purposes */
	bool use_role; /**< Whether to use a reST role or directive for the ID */

	/**
	 * Set the short_desc member to be a subset of reST_doc_strings.
	 * Specifically, short_desc will be everything in reST_doc_strings
	 * up until the first period or first empty string list element found.
	 */
	void FormulateShortDesc();

private:
};

/**
 * Map identifiers to their broxygen documentation objects.
 */
extern map<string, BroDocObj*> doc_ids;

#endif
