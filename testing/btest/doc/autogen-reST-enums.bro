# @TEST-EXEC: bro --doc-scripts %INPUT
# @TEST-EXEC: btest-diff autogen-reST-enums.rst

## There's tons of ways an enum can look...
type TestEnum1: enum {
    ## like this
    ONE,
    TWO, ##< or like this
    ## multiple
    ## comments
    THREE, ##< and even
           ##< more comments
};

## The final comma is optional
type TestEnum2: enum {
    ## like this
    A,
    B, ##< or like this
    ## multiple
    ## comments
    C  ##< and even
           ##< more comments
};

## redefs should also work
redef enum TestEnum1 += {
    ## adding another
    FOUR ##< value
};

## now with a comma
redef enum TestEnum1 += {
    ## adding another
    FIVE, ##< value
};
