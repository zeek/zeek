# Prototypes for functions implemented in binpac-lib.pac.

function bytestring_to_int(s: const_bytestring, base: int): int;
function bytestring_to_double(s: const_bytestring): double;

function bytestring_casecmp(s1: const_bytestring, s2: const_charptr): int;

# True if s2 is a (case-insensitive) prefix of s1.
function bytestring_caseprefix(s1: const_bytestring, s2: const_charptr): bool;
