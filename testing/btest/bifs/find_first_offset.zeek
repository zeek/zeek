# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

event zeek_init()
    {
    local s = "banana_bandana_nanana";
    
    print "String:", s;
    print "Length:", |s|;
    print "---------------------------------";

    # --- find_first Tests ---
    print "find_first (offset 0):  ", find_first(s, /ana/);       
    print "find_first (offset 2):  ", find_first(s, /ana/, 2);    
    print "find_first (offset 5):  ", find_first(s, /ana/, 5);    
    print "find_first (offset 15): ", find_first(s, /ana/, 15);   
    print "find_first (offset 18): ", find_first(s, /ana/, 18);   
    print "find_first (OOB 99):    ", find_first(s, /ana/, 99);   
    print "find_first (fail):      ", find_first(s, /banana/, 10);   

    print "---------------------------------";

    # --- find_last Tests ---
    print "find_last (offset 0):   ", find_last(s, /ana/);        
    print "find_last (offset 10):  ", find_last(s, /ana/, 10);    
    print "find_last (offset 18):  ", find_last(s, /ana/, 18);    
    print "find_last (OOB 99):     ", find_last(s, /ana/, 99);    
    print "find_last (fail):       ", find_last(s, /banana/, 10);    
    }
