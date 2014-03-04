# General purpose file magic signatures.

signature file-plaintext {
    file-magic /([[:print:][:space:]]+)/
    file-mime "text/plain", -20
}

signature file-binary {
    file-magic /(.*)([^[:print:][:space:]]+)/
    file-mime "binary", -10
}
