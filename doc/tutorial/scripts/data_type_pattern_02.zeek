event zeek_init()
    {
    local test_string = "equality";

    local test_pattern = /equal/;
    print fmt("%s and %s %s equal", test_string, test_pattern, test_pattern == test_string ? "are" : "are not");
    
    test_pattern = /equality/;
    print fmt("%s and %s %s equal", test_string, test_pattern, test_pattern == test_string ? "are" : "are not");
    }
