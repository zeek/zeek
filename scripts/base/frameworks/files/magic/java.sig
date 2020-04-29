signature file-jar {
	file-mime "application/java-archive", 100
	file-magic /^PK\x03\x04.{1,200}\x14\x00..META-INF\/MANIFEST\.MF/
}

signature file-java-applet {
	file-mime "application/x-java-applet", 71
	file-magic /^\xca\xfe\xba\xbe...[\x2d-\x34]/
}

# JAR compressed with pack200
signature file-jar-pack200 {
	file-mime "application/x-java-pack200", 1
	file-magic /^\xca\xfe\xd0\x0d./
}

# Java Web Start file.
signature file-jnlp {
	file-magic /^\<jnlp\x20/
	file-mime "application/x-java-jnlp-file", 100
}

signature file-java-keystore {
	file-mime "application/x-java-keystore", 70
	file-magic /^\xfe\xed\xfe\xed/
}

signature file-java-jce-keystore {
	file-mime "application/x-java-jce-keystore", 70
	file-magic /^\xce\xce\xce\xce/
}
