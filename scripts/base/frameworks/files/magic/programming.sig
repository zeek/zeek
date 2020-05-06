signature file-shellscript {
	file-mime "text/x-shellscript", 250
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?(ba|tc|c|z|fa|ae|k)?sh/
}

signature file-perl {
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?perl/
	file-mime "text/x-perl", 60
}

signature file-ruby {
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?ruby/
	file-mime "text/x-ruby", 60
}

signature file-python {
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?python/
	file-mime "text/x-python", 60
}

signature file-awk {
	file-mime "text/x-awk", 60
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?(g|n)?awk/
}

signature file-tcl {
	file-mime "text/x-tcl", 60
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?(wish|tcl)/
}

signature file-lua {
	file-mime "text/x-lua", 49
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?lua/
}

signature file-javascript {
	file-mime "application/javascript", 60
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?node(js)?/
}

signature file-javascript2 {
	file-mime "application/javascript", 60
	file-magic /^[\x0d\x0a[:blank:]]*<[sS][cC][rR][iI][pP][tT][[:blank:]]+([tT][yY][pP][eE]|[lL][aA][nN][gG][uU][aA][gG][eE])=['"]?([tT][eE][xX][tT]\/)?[jJ][aA][vV][aA][sS][cC][rR][iI][pP][tT]/
}

signature file-javascript3 {
	file-mime "application/javascript", 60
	# This seems to be a somewhat common idiom in javascript.
	file-magic /^[\x0d\x0a[:blank:]]*for \(;;\);/
}

signature file-javascript4 {
	file-mime "application/javascript", 60
	file-magic /^[\x0d\x0a[:blank:]]*document\.write(ln)?[:blank:]?\(/
}

signature file-javascript5 {
	file-mime "application/javascript", 60
	file-magic /^\(function\(\)[[:blank:]\n]*\{/
}

signature file-javascript6 {
	file-mime "application/javascript", 60
	file-magic /^[\x0d\x0a[:blank:]]*<script>[\x0d\x0a[:blank:]]*(var|function) /
}

signature file-php {
	file-mime "text/x-php", 60
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?php/
}

signature file-php2 {
	file-magic /^.*<\?php/
	file-mime "text/x-php", 40
}

signature file-batch1 {
	file-mime "text/x-msdos-batch", 110
	file-magic /\x40 *[eE][cC][hH][oO] {1,}[oO][fF][fF]/
}

signature file-batch2 {
	file-mime "text/x-msdos-batch", 60
	file-magic /\x40[rR][eE][mM]/
}

signature file-batch3 {
	file-mime "text/x-msdos-batch", 70
	file-magic /\x40[sS][eE][tT] {1,}/
}

# M4 macro processor script text
signature file-m4 {
	file-mime "text/x-m4", 40
	file-magic /^dnl /
}
