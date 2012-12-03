// See the file "COPYING" in the main distribution directory for copyright.

#ifndef AsciiInputOutput_h
#define AsciiInputOutput_h

class AsciiInputOutput {
	public: 
		// converts a threading value to the corresponding ascii representation
		// returns false & logs an error with reporter in case an error occurs
		bool ValToText(ODesc* desc, Value* val, const Field* field);

};

#endif /* AsciiInputOuput_h */
