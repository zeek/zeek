# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o pe.hlto pe.spicy zeek_pe.spicy pe.evt
# @TEST-EXEC: zeek -r ${TRACES}/pe/pe-single.trace pe.hlto %INPUT ENABLE=T
# @TEST-EXEC: cat files.log | zeek-cut source analyzers filename mime_type >>output
# @TEST-EXEC: zeek -r ${TRACES}/pe/pe-single.trace pe.hlto %INPUT ENABLE=F
# @TEST-EXEC: cat files.log | zeek-cut source analyzers filename mime_type >>output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Test replacing an existing file analyzer, and also toggling the Spicy one on and off

const ENABLE = T &redef;

event zeek_init() {
    if ( ENABLE )
        Spicy::enable_file_analyzer(Files::ANALYZER_SPICY_PE);
    else
        Spicy::disable_file_analyzer(Files::ANALYZER_SPICY_PE);
}

event pe_dos_header(f: fa_file, h: PE::DOSHeader)
	{
	print "pe_dos_header", h;
	}

# @TEST-START-FILE pe.spicy
module PE;
import spicy;
%byte-order = spicy::ByteOrder::Little;

public type ImageFile = unit {
    %mime-type = "application/x-dosexec";

    dosHeader: DOS_Header;
};

type DOS_Header = unit {
    magic:                  b"MZ";
    bytesInLastPage:        uint16;
    pagesInFile:            uint16;
    relocations:            uint16;
    paragraphsInHeader:     uint16;
    minExtraParagraphs:     uint16;
    maxExtraParagraphs:     uint16;
    initialRelativeSS:      uint16;
    initialSP:              uint16;
    checksum:               uint16;
    initialIP:              uint16;
    initialRelativeCS:      uint16;
    relocationTableAddress: uint16;
    overlayNumber:          uint16;
    reserved1:              bytes &size=8;
    oemID:                  uint16;
    oemInfo:                uint16;
    reserved2:              bytes &size=20;
    peHeaderOffset:         uint32;
};
# @TEST-END-FILE

# @TEST-START-FILE zeek_pe.spicy
module Zeek_PE;
import PE;

type DOSHeader = tuple<
    signature                : bytes,
    used_bytes_in_last_page  : uint64,
    file_in_pages            : uint64,
    num_reloc_items          : uint64,
    header_in_paragraphs     : uint64,
    min_extra_paragraphs     : uint64,
    max_extra_paragraphs     : uint64,
    init_relative_ss         : uint64,
    init_sp                  : uint64,
    checksum                 : uint64,
    init_ip                  : uint64,
    init_relative_cs         : uint64,
    addr_of_reloc_table      : uint64,
    overlay_num              : uint64,
    oem_id                   : uint64,
    oem_info                 : uint64,
    addr_of_new_exe_header   : uint64
    >;

public function makeDOSHeader(h: PE::DOS_Header): DOSHeader
    {
    return (
            b"MZ (Spicy)",
            h.bytesInLastPage,
            h.pagesInFile,
            h.relocations,
            h.paragraphsInHeader,
            h.minExtraParagraphs,
            h.maxExtraParagraphs,
            h.initialRelativeSS,
            h.initialSP,
            h.checksum,
            h.initialIP,
            h.initialRelativeCS,
            h.relocationTableAddress,
            h.overlayNumber,
            h.oemID,
            h.oemInfo,
            h.peHeaderOffset,
           );
    }
# @TEST-END-FILE

# @TEST-START-FILE pe.evt
file analyzer spicy::PE:
    parse with PE::ImageFile,
    replaces PE,
    mime-type application/x-dosexec;

import Zeek_PE;

on PE::DOS_Header -> event pe_dos_header($file, Zeek_PE::makeDOSHeader(self));
# @TEST-END-FILE
