// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <ctime>

namespace zeek::zeekygen::detail{

/**
 * Abstract base class for any thing that Zeekygen can document.
 */
class Info {

public:

	/**
	 * Ctor.
	 */
	Info()
		{ }

	/**
	 * Dtor.
	 */
	virtual ~Info()
		{ }

	/**
	 * @return The time any information related to the object was last modified.
	 */
	time_t GetModificationTime() const
		{ return DoGetModificationTime(); }

	/**
	 * @return A unique name for the documentable object.
	 */
	std::string Name() const
		{ return DoName(); }

	/**
	 * Get a reST representation of the object and any associated documentation.
	 * @param roles_only True if the reST should only use cross-referencing role
	 * syntax to refer itself instead of using a directive (which declares this
	 * reST the authoritative "anchor" for cross-references).
	 * @return A reST representation of the object and associated documentation.
	 */
	std::string ReStructuredText(bool roles_only = false) const
		{ return DoReStructuredText(roles_only); }

	/**
	 * Perform any remaining info gathering/initialization that can only be done
	 * after all script parsing is complete.
	 */
	void InitPostScript()
		{ DoInitPostScript(); }

private:

	virtual time_t DoGetModificationTime() const = 0;

	virtual std::string DoName() const = 0;

	virtual std::string DoReStructuredText(bool roles_only) const = 0;

	virtual void DoInitPostScript()
		{ }
};

} // namespace zeek::zeekygen::detail
