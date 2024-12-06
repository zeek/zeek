# Python magic numbers can be updated/added by looking at the list at
# https://github.com/python/cpython/blob/main/Include/internal/pycore_magic_number.h
# The numbers in the list are converted to little-endian and then to hex for the
# file-magic entries below.

# Python 1 bytecode
signature file-pyc-1 {
	file-magic /^(\xfc\xc4|\x99\x4e)\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}

# Python 2 bytecode
signature file-pyc-2 {
	file-magic /^(\x87\xc6|[\x2a\x2d]\xed|[\x3b\x45\x59\x63\x6d\x77\x81\x8b\x8c\x95\x9f\xa9\xb3\xc7\xd1\xdb\xe5\xef\xf9]\xf2|\x03\xf3)\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}

# Python 3.0 bytecode
signature file-pyc-3-0 {
	file-magic /^([\xb8\xc2\xcc\xd6\xe0\xea\xf4\xf5\xff]\x0b|[\x09\x13\x1d\x1f\x27\x3b]\x0c)\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}


# Python 3.1 bytecode
signature file-pyc-3-1 {
	file-magic /^[\x45\x4f]\x0c\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}


# Python 3.2 bytecode
signature file-pyc-3-2 {
	file-magic /^[\x58\x62\x6c]\x0c\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}

# Python 3.3 bytecode
signature file-pyc-3-3 {
	file-magic /^[\x76\x80\x94\x9e]\x0c\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}


# Python 3.4 bytecode
signature file-pyc-3-4 {
	file-magic /^[\xb2\xcc\xc6\xd0\xda\xe4\xee]\x0c\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}

# Python 3.5 bytecode
signature file-pyc-3-5 {
	file-magic /^(\xf8\x0c|[\x02\x0c\x16\x17]\x0d)\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}

# Python 3.6 bytecode
signature file-pyc-3-6 {
	file-magic /^[\x20\x21\x2a-\x2d\x2f-\x33]\x0d\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}

# Python 3.7 bytecode
signature file-pyc-3-7 {
	file-magic /^[\x3e-\x42]\x0d\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}

# Python 3.8 bytecode
signature file-pyc-3-8 {
	file-magic /^[\x48\x49\x52-\x55]\x0d\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}

# Python 3.9 bytecode
signature file-pyc-3-9 {
	file-magic /^[\x5c-\x61]\x0d\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}

# Python 3.10 bytecode
signature file-pyc-3-10 {
	file-magic /^[\x66-\x6f]\x0d\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}

# Python 3.11 bytecode
signature file-pyc-3-11 {
	file-magic /^[\x7a-\xa7]\x0d\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}

# Python 3.12 bytecode
signature file-pyc-3-12 {
	file-magic /^[\xac-\xcb]\x0d\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}

# Python 3.13 bytecode
signature file-pyc-3-13 {
	file-magic /^[\xde-\xf3]\x0d\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}

# Python 3.14 bytecode
# This is in pre-release at this time, and may need to be updated as new
# versions come out.
signature file-pyc-3-14 {
	file-magic /^[\x10-\x19]\x0e\x0d\x0a/
	file-mime "application/x-python-bytecode", 80
}
