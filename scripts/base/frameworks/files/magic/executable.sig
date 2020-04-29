# Portable Executable
signature file-pe {
	file-mime "application/x-dosexec", 51
	file-magic /MZ/
}

signature file-elf-object {
	file-mime "application/x-object", 50
	file-magic /\x7fELF[\x01\x02](\x01.{10}\x01\x00|\x02.{10}\x00\x01)/
}

signature file-elf {
	file-mime "application/x-executable", 50
	file-magic /\x7fELF[\x01\x02](\x01.{10}\x02\x00|\x02.{10}\x00\x02)/
}

signature file-elf-sharedlib {
	file-mime "application/x-sharedlib", 50
	file-magic /\x7fELF[\x01\x02](\x01.{10}\x03\x00|\x02.{10}\x00\x03)/
}

signature file-elf-coredump {
	file-mime "application/x-coredump", 50
	file-magic /\x7fELF[\x01\x02](\x01.{10}\x04\x00|\x02.{10}\x00\x04)/
}

# Mac OS X Mach-O executable
signature file-mach-o {
	file-magic /^[\xce\xcf]\xfa\xed\xfe/
	file-mime "application/x-mach-o-executable", 100
}

# Mac OS X Universal Mach-O executable
signature file-mach-o-universal {
	file-magic /^\xca\xfe\xba\xbe..\x00[\x01-\x14]/
	file-mime "application/x-mach-o-executable", 100
}

# Emacs/XEmacs byte-compiled Lisp
signature file-elc {
	file-mime "application/x-elc", 10
	file-magic /\x3bELC[\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff]/
}

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
