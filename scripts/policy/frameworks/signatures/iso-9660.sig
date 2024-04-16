# ISO 9660 disk image: First 16 sectors (2k) are arbitrary data.
# The following sector is a volume descriptor with magic string "CD001"
# at offset 1: 16 * 2048 + 1 = 32769.
#
# However, we do not use exact offset matching /^.{32769}CD001/ as this
# results in major performance degradation.
signature file-iso9660 {
        file-mime "application/x-iso9660-image", 99
        file-magic /.*CD001\x01/
}
