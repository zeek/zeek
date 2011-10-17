
#ifndef INPUTREADERASCII_H
#define INPUTREADERASCII_H

#include "InputReader.h"

class InputReaderAscii : public InputReader {
public:
    InputReaderAscii();
    ~InputReaderAscii();
    
    static InputReader* Instantiate() { return new InputReaderAscii; }
    
protected:
    
private:
};


#endif /* INPUTREADERASCII_H */
