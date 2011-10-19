// See the file "COPYING" in the main distribution directory for copyright.
// 
// Same notes about thread safety as in LogWriter.h apply.


#ifndef INPUTREADER_H
#define INPUTREADER_H

#include "InputMgr.h"
#include "BroString.h"

class InputReader {
public:
    InputReader();
    virtual ~InputReader();
	
	bool Init(string source, string eventName);
    
protected:
    // Methods that have to be overwritten by the individual readers
	
	// Reports an error to the user.
	void Error(const char *msg);
	
	// The following methods return the information as passed to Init().
	const string Source() const	{ return source; }

private:
    friend class InputMgr;
	
	string source;
    
    // When an error occurs, this method is called to set a flag marking the 
    // writer as disabled.
    
    bool disabled;
    
    bool Disabled() { return disabled; }
};


#endif /* INPUTREADER_H */
