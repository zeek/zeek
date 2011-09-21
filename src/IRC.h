// An IRC analyzer contributed by Roland Gruber.

#ifndef irc_h
#define irc_h
#include "TCP.h"

/**
* \brief Main class for analyzing IRC traffic.
*/
class IRC_Analyzer : public TCP_ApplicationAnalyzer {
	enum { WAIT_FOR_REGISTRATION, REGISTERED, };
	enum { NO_ZIP, ACCEPT_ZIP, ZIP_LOADED, };
public:
	/**
	* \brief Constructor, builds a new analyzer object.
	*/
	IRC_Analyzer(Connection* conn);

	/**
	* \brief Called when connection is closed.
	*/
	virtual void Done();

	/**
	* \brief New input line in network stream.
	*
	* \param len the line length
	* \param data pointer to line start
	* \param orig was this data sent from connection originator?
	*/
	virtual void DeliverStream(int len, const u_char* data, bool orig);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{
		return new IRC_Analyzer(conn);
		}

	static bool Available();

protected:
	int orig_status;
	int orig_zip_status;
	int resp_status;
	int resp_zip_status;

private:
	/** \brief counts number of invalid IRC messages */
	int invalid_msg_count;

	/** \brief maximum count of invalid IRC messages */
	int invalid_msg_max_count;

	/**
	* \brief Splits a string into its words which are separated by
	* the split character.
	*
	* \param input string which will be splitted
	* \param split character which separates the words
	* \return vector containing words
	*/
	vector<string> SplitWords(const string input, const char split);

};

#endif
