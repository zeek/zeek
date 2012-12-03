// See the file "COPYING" in the main distribution directory for copyright.

#ifndef AsciiInputOutput_h
#define AsciiInputOutput_h

#include "Desc.h"
#include "threading/MsgThread.h"

class AsciiInputOutput {
	public: 
		AsciiInputOutput(threading::MsgThread*, const string & separator, const string & set_separator, 
				const string & empty_field, const string & unset_field);
		~AsciiInputOutput();


		// converts a threading value to the corresponding ascii representation
		// returns false & logs an error with reporter in case an error occurs
		bool ValToODesc(ODesc* desc, threading::Value* val, const threading::Field* field) const;

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


	private:

		string separator;
		string set_separator;
		string empty_field;
		string unset_field;
		string meta_prefix;

		threading::MsgThread* thread;
};

#endif /* AsciiInputOuput_h */
