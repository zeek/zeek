// See the file "COPYING" in the main distribution directory for copyright.

#ifndef AsciiInputOutput_h
#define AsciiInputOutput_h

#include "../Desc.h"
#include "MsgThread.h"

class AsciiInputOutput {
	public: 

		/** 
		 * A struct to pass the necessary initialization values to the AsciiInputOutput module
		 * on startup
		 */
		struct SeparatorInfo 
			{
			//const string separator;
			string set_separator;
			string empty_field;
			string unset_field;
			string meta_prefix;

			// Constructor that leaves separators, etc empty.
			// Use if you just need functionality like StringToAddr, etc.
			SeparatorInfo() { };

			// Constructor that defines all separators, etc.
			// Use if you need either ValToODesc or EntryToVal.
			SeparatorInfo(const string & set_separator, 
				 const string & unset_field, const string & empty_field);

			// Constructor that defines all separators, etc, besides empty_field, which is not needed for many
			// non-ascii-based io sources.
			// Use if you need either ValToODesc or EntryToVal.
			SeparatorInfo(const string & set_separator, 
				 const string & unset_field);
			};

		/**
		 * Constructor
		 *
		 * @param t The thread that uses this class instance. Used to access thread
		 * message passing methods
		 *
		 * @param info
		 * SeparatorInfo structure defining the necessary separators
		 */
		AsciiInputOutput(threading::MsgThread* t, const SeparatorInfo info);
	
		// Destructor
		~AsciiInputOutput();

		// converts a threading value to the corresponding ascii representation
		// returns false & logs an error with reporter in case an error occurs
		bool ValToODesc(ODesc* desc, threading::Value* val, const threading::Field* field) const;

		// convert the ascii representation of a field into a Value
		threading::Value* StringToVal(string s, string name, TypeTag type, TypeTag subtype = TYPE_ERROR) const;

		/** Helper method to render an IP address as a string.
		  *
		  * @param addr The address.
		  *
		  * @return An ASCII representation of the address.
		  */
		static string Render(const threading::Value::addr_t& addr);

		/** Helper method to render an subnet value as a string.
		  *
		  * @param addr The address.
		  *
		  * @return An ASCII representation of the address.
		  */
		static string Render(const threading::Value::subnet_t& subnet);

		/** Helper method to render a double in Bro's standard precision.
		  *
		  * @param d The double.
		  *
		  * @return An ASCII representation of the double.
		  */
		static string Render(double d);

		/**
		 *  Convert a string into a TransportProto. This is just a utility
		 *  function for Readers.
		 *
		 * @param proto the transport protocol
		 */
		TransportProto StringToProto(const string &proto) const;

		/**
		 * Convert a string into a Value::addr_t.  This is just a utility
		 * function for Readers.
		 *
		 * @param addr containing an ipv4 or ipv6 address
		 */
		threading::Value::addr_t StringToAddr(const string &addr) const;

	private:
		bool CheckNumberError(const string& s, const char * end) const;

		SeparatorInfo separators;

		threading::MsgThread* thread;
};

#endif /* AsciiInputOuput_h */
