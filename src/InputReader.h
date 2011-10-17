// See the file "COPYING" in the main distribution directory for copyright.
// 
// Same notes about thread safety as in LogWriter.h apply.


#ifndef INPUTREADER_H
#define INPUTREADER_H

class InputReader {
public:
    InputReader();
    virtual ~InputReader();
    
protected:
    // Methods that have to be overwritten by the individual readers
    
private:
    friend class InputMgr;
    
    // When an error occurs, this method is called to set a flag marking the 
    // writer as disabled.
    
    bool disabled;
    
    bool Disabled() { return disabled; }
};


#endif /* INPUTREADER_H */
