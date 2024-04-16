#! /bin/sh

# Finds script functions known to the event engine by searching through
# the C++ code. Invoke with the top-level src/ directory as an argument.

# Search for event engine code that looks up script functions.
grep -h -r -w find_func $* |

    # Trim out whatever is leading up to the name.
    sed 's,.*find_func,,' |

    # Make sure we're dealing with a literal name in quotes.
    grep '"' |

    # Don't be fooled by -O gen-C++, which has code-to-generate-code that
    # uses find_Func.
    grep -v '\\"' |

    # Get rid of the quotes.
    sed 's,^[^"]*",,;s,"[^"]*$,,' |

    # Produce a regularized list for easy diff'ing.
    sort -u
