
#ifndef INPUTREADERASCII_H
#define INPUTREADERASCII_H

#include "InputReader.h"
#include <fstream>
#include <iostream>


class InputReaderAscii : public InputReader {
public:
    InputReaderAscii();
    ~InputReaderAscii();
    
    static InputReader* Instantiate() { return new InputReaderAscii; }
    
protected:
	
	virtual bool DoInit(string path, int num_fields,
						const LogField* const * fields);
	virtual void DoFinish();
    
private:
	
	ifstream* file;
	string fname;
};


#endif /* INPUTREADERASCII_H */
