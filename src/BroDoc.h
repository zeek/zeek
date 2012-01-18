#ifndef brodoc_h
#define brodoc_h

#include <cstdio>
#include <cstdarg>
#include <string>
#include <list>

#include "BroDocObj.h"

/**
 * This class is used to gather all data relevant to the automatic generation
 * of a reStructuredText (reST) document from a given Bro script.
 */
class BroDoc {
public:
	/**
	 * BroDoc constructor
	 * Given a Bro script, opens new file in the current working directory
	 * that will contain reST documentation generated from the parsing
	 * of the Bro script.  The new reST file will be named similar to
	 * the filename of the Bro script that generates it, except any
	 * ".bro" file extension is stripped and ".rst" takes it place.
	 * If the filename doesn't end in ".bro", then ".rst" is just appended.
	 * Any '/' characters in the reST file name that result from choice of
	 * the 'rel' parameter are replaced with '^'.
	 * @param rel A string representing a subpath of the root Bro script
	 *        source/install directory in which the source file is located.
	 *        It can also be an absolute path, but then the parameter is
	 *        ignored and the document title is just derived from file name
	 * @param abs The absolute path to the Bro script for which to generate
	 *        documentation.
	 */
	BroDoc(const std::string& rel, const std::string& abs);

	/**
	 * BroDoc destructor
	 * Closes the file that was opened by the constructor and frees up
	 * memory taken by BroDocObj objects.
	 */
	virtual ~BroDoc();

	/**
	 * Write out full reST documentation for the Bro script that was parsed.
	 * BroDoc's default implementation of this function will care
	 * about whether declarations made in the Bro script are part of
	 * the public versus private interface (whether things are declared in
	 * the export section).
	 */
	virtual void WriteDocFile() const;

	/**
	 * Schedules some summarizing text to be output directly into the reST doc.
	 * This should be called whenever the scanner sees a line in the Bro script
	 * starting with "##!"
	 * @param s The summary text to add to the reST doc.
	 */
	void AddSummary(const std::string& s)	{ summary.push_back(s); }

	/**
	 * Schedules an import (@load) to be documented.
	 * If the script being loaded has a .bro suffix, it is internally stripped.
	 * This should be called whenever the scanner sees an @load.
	 * @param s The name of the imported script.
	 */
	void AddImport(const std::string& s);

	/**
	 * Schedules a namespace (module) to be documented.
	 * This should be called whenever the parser sees a TOK_MODULE.
	 * @param s The namespace (module) identifier's name.
	 */
	void AddModule(const std::string& s)	{ modules.push_back(s); }

	/**
	 * Sets the way the script changes the "capture_filters" table.
	 * This is determined by the scanner checking for changes to
	 * the "capture_filters" table after each of Bro's input scripts
	 * (given as command line arguments to Bro) are finished being parsed.
	 * @param s The value "capture_filters" as given by TableVal::Describe()
	 */
	void SetPacketFilter(const std::string& s);

	/**
	 * Schedules documentation of a given set of ports being associated
	 * with a particular analyzer as a result of the current script
	 * being loaded -- the way the "dpd_config" table is changed.
	 * @param analyzer An analyzer that changed the "dpd_config" table.
	 * @param ports The set of ports assigned to the analyzer in table.
	 */
	void AddPortAnalysis(const std::string& analyzer, const std::string& ports);

	/**
	 * Schedules documentation of a script option.  An option is
	 * defined as any variable in the script that is declared 'const'
	 * and has the '&redef' attribute.
	 * @param o A pointer to a BroDocObj which contains the internal
	 *        Bro language representation of the script option and
	 *        also any associated comments about it.
	 */
	void AddOption(const BroDocObj* o)
		{
		options.push_back(o);
		all.push_back(o);
		}

	/**
	 * Schedules documentation of a script constant.  An option is
	 * defined as any variable in the script that is declared 'const'
	 * and does *not* have the '&redef' attribute.
	 * @param o A pointer to a BroDocObj which contains the internal
	 *        Bro language representation of the script constant and
	 *        also any associated comments about it.
	 */
	void AddConstant(const BroDocObj* o)
		{
		constants.push_back(o);
		all.push_back(o);
		}

	/**
	 * Schedules documentation of a script state variable.  A state variable
	 * is defined as any variable in the script that is declared 'global'
	 * @param o A pointer to a BroDocObj which contains the internal
	 *        Bro language representation of the script state variable
	 *        and also any associated comments about it.
	 */
	void AddStateVar(const BroDocObj* o)
		{
		state_vars.push_back(o);
		all.push_back(o);
		}

	/**
	 * Schedules documentation of a type declared by the script.
	 * @param o A pointer to a BroDocObj which contains the internal
	 *        Bro language representation of the script option and
	 *        also any associated comments about it.
	 */
	void AddType(const BroDocObj* o)
		{
		types.push_back(o);
		all.push_back(o);
		}

	/**
	 * Schedules documentation of a Notice (enum redef) declared by script
	 * @param o A pointer to a BroDocObj which contains the internal
	 *        Bro language representation of the Notice and also
	 *        any associated comments about it.
	 */
	void AddNotice(const BroDocObj* o)
		{
		notices.push_back(o);
		all.push_back(o);
		}

	/**
	 * Schedules documentation of an event declared by the script.
	 * @param o A pointer to a BroDocObj which contains the internal
	 *        Bro language representation of the script event and
	 *        also any associated comments about it.
	 */
	void AddEvent(const BroDocObj* o)
		{
		events.push_back(o);
		all.push_back(o);
		}

	/**
	 * Schedules documentation of an event handler declared by the script.
	 * @param o A pointer to a BroDocObj which contains the internal
	 *        Bro language representation of the script event handler and
	 *        also any associated comments about it.
	 */
	void AddEventHandler(const BroDocObj* o)
		{
		event_handlers.push_back(o);
		all.push_back(o);
		}

	/**
	 * Schedules documentation of a function declared by the script.
	 * @param o A pointer to a BroDocObj which contains the internal
	 *        Bro language representation of the script function and
	 *        also any associated comments about it.
	 */
	void AddFunction(BroDocObj* o);

	/**
	 * Schedules documentation of a redef done by the script
	 * @param o A pointer to a BroDocObj which contains the internal
	 *        Bro language representation of the script identifier
	 *        that was redefined and also any associated comments.
	 */
	void AddRedef(const BroDocObj* o)
		{
		redefs.push_back(o);
		all.push_back(o);
		}

	/**
	 * Gets the name of the Bro script source file for which reST
	 * documentation is being generated.
	 * @return A char* to the start of the source file's name.
	 */
	const char* GetSourceFileName() const
		{
		return source_filename.c_str();
		}

	/**
	 * Gets the name of the generated reST documentation file.
	 * @return A char* to the start of the generated reST file's name.
	 */
	const char* GetOutputFileName() const
		{
		return reST_filename.c_str();
		}

protected:
	FILE* reST_file;
	std::string reST_filename;
	std::string source_filename;	// points to the basename of source file
	std::string downloadable_filename; // file that will be linked for download
	std::string doc_title;
	std::string packet_filter;

	std::list<std::string> modules;
	std::list<std::string> summary;
	std::list<std::string> imports;
	std::list<std::string> port_analysis;

	typedef std::list<const BroDocObj*> BroDocObjList;
	typedef std::map<std::string, BroDocObj*> BroDocObjMap;

	BroDocObjList options;
	BroDocObjList constants;
	BroDocObjList state_vars;
	BroDocObjList types;
	BroDocObjList notices;
	BroDocObjList events;
	BroDocObjList event_handlers;
	BroDocObjMap functions;
	BroDocObjList redefs;

	BroDocObjList all;

	/**
	 * Writes out a list of strings to the reST document.
	 * If the list is empty, prints a newline character.
	 * @param format A printf style format string for elements of the list
	 *        except for the last one in the list
	 * @param last_format A printf style format string to use for the last
	 *        element of the list
	 * @param l A reference to a list of strings
	 */
	void WriteStringList(const char* format, const char* last_format,
			const std::list<std::string>& l) const;

	/**
	 * @see WriteStringList(const char*, const char*,
	 *                      const std::list<std::string>&>)
	 */
	void WriteStringList(const char* format,
			const std::list<std::string>& l) const
		{
		WriteStringList(format, format, l);
		}


	/**
	 * Writes out a table of BroDocObj's to the reST document
	 * @param l A list of BroDocObj pointers
	 */
	void WriteBroDocObjTable(const BroDocObjList& l) const;

	/**
	 * Writes out a list of BroDocObj objects to the reST document
	 * @param l A list of BroDocObj pointers
	 * @param wantPublic If true, filter out objects that are not declared
	 *        in the global scope.  If false, filter out those that are in
	 *        the global scope.
	 * @param heading The title of the section to create in the reST doc.
	 * @param underline The character to use to underline the reST
	 *        section heading.
	 * @param isShort Whether to write the full documentation or a "short"
	 *        version (a single sentence)
	 */
	void WriteBroDocObjList(const BroDocObjList& l, bool wantPublic,
			const char* heading, char underline,
			bool isShort) const;

	/**
	 * Wraps the BroDocObjMap into a BroDocObjList and the writes that list
	 * to the reST document
	 * @see WriteBroDocObjList(const BroDocObjList&, bool, const char*, char,
	        bool)
	 */
	void WriteBroDocObjList(const BroDocObjMap& m, bool wantPublic,
			const char* heading, char underline,
			bool isShort) const;

	/**
	 * Writes out a list of BroDocObj objects to the reST document
	 * @param l A list of BroDocObj pointers
	 * @param heading The title of the section to create in the reST doc.
	 * @param underline The character to use to underline the reST
	 *        section heading.
	 */
	void WriteBroDocObjList(const BroDocObjList& l, const char* heading,
			char underline) const;

	/**
	 * Writes out a list of BroDocObj objects to the reST document
	 * @param l A list of BroDocObj pointers
	 */
	void WriteBroDocObjList(const BroDocObjList& l) const;

	/**
	 * Wraps the BroDocObjMap into a BroDocObjList and the writes that list
	 * to the reST document
	 * @see WriteBroDocObjList(const BroDocObjList&, const char*, char)
	 */
	void WriteBroDocObjList(const BroDocObjMap& m, const char* heading,
			char underline) const;

	/**
	 * A wrapper to fprintf() that always uses the reST document
	 * for the FILE* argument.
	 * @param format A printf style format string.
	 */
	void WriteToDoc(const char* format, ...) const;

	/**
	 * Writes out a reST section heading
	 * @param heading The title of the heading to create
	 * @param underline The character to use to underline the section title
	 *        within the reST document
	 */
	void WriteSectionHeading(const char* heading, char underline) const;

	/**
	 * Writes out given number of characters to reST document
	 * @param c the character to write
	 * @param n the number of characters to write
	 */
	void WriteRepeatedChar(char c, size_t n) const;

	/**
	 * Writes out the reST for either the script's public or private interface
	 * @param heading The title of the interfaces section heading
	 * @param underline The underline character to use for the interface
	 *        section
	 * @param subunderline The underline character to use for interface
	 *        sub-sections
	 * @param isPublic Whether to write out the public or private script
	 *        interface
	 * @param isShort Whether to write out the full documentation or a "short"
	 *        description (a single sentence)
	 */
	void WriteInterface(const char* heading, char underline, char subunderline,
			bool isPublic, bool isShort) const;
private:

	/**
	 * Frees memory allocated to BroDocObj's objects in a given list.
	 * @param a reference to a list of BroDocObj pointers
	 */
	void FreeBroDocObjPtrList(BroDocObjList& l);

	static bool IsPublicAPI(const BroDocObj* o)
		{
		return o->IsPublicAPI();
		}

	static bool IsPrivateAPI(const BroDocObj* o)
		{
		return ! o->IsPublicAPI();
		}

    struct replace_slash {
        void operator()(char& c)
            {
            if ( c == '/' ) c = '^';
            }
    };
};

#endif
