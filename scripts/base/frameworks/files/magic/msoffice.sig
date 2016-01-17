
# This signature is non-specific and terrible but after
# searching for a long time there doesn't seem to be a 
# better option.  
signature file-msword {
	file-magic /^\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1/
	file-mime "application/msword", 50
}

signature file-ooxml {
	file-magic /^PK\x03\x04\x14\x00\x06\x00/
	file-mime "application/vnd.openxmlformats-officedocument", 50
}

signature file-docx {
	file-magic /^PK\x03\x04.{26}(\[Content_Types\]\.xml|_rels\x2f\.rels|word\x2f).*PK\x03\x04.{26}word\x2f/
	file-mime "application/vnd.openxmlformats-officedocument.wordprocessingml.document", 80
}

signature file-xlsx {
	file-magic /^PK\x03\x04.{26}(\[Content_Types\]\.xml|_rels\x2f\.rels|xl\2f).*PK\x03\x04.{26}xl\x2f/
	file-mime "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", 80
}

signature file-pptx {
	file-magic /^PK\x03\x04.{26}(\[Content_Types\]\.xml|_rels\x2f\.rels|ppt\x2f).*PK\x03\x04.{26}ppt\x2f/
	file-mime "application/vnd.openxmlformats-officedocument.presentationml.presentation", 80
}

signature file-msaccess {
	file-mime "application/x-msaccess", 180
	file-magic /.{4}Standard (Jet|ACE) DB\x00/
}

