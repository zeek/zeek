type Files = record {
	file: File[] &until ($element.signature == 0x06054b50);
} &byteorder=littleendian;

type File = record {
	signature : uint32;
	sig_switch: case signature of {
		0x04034b50 -> local_file        : LocalFileHeader;
		0x08064b50 -> extra_data        : ExtraDataHeader;
		0x02014b50 -> central_dir       : CentralDirectoryStructure;
		0x05054b50 -> digital_sig       : DigitalSignature;
		0x06054b50 -> end_of_central_dir: EndOfCentralDirectoryStructure;
	};
} &byteorder=littleendian;

type LocalFileHeader = record {
	version			: uint16;
	flags			: uint16;
	compression_method	: uint16;
	last_modified_time	: uint16;
	last_modified_date	: uint16;
	crc32			: uint32;
	compressed_size		: uint32;
	uncompressed_size	: uint32;
	file_name_length	: uint32;
	extra_field_length	: uint32;
	is_encrypted		: case (flags % 1) of {
		0 -> no_crypt         : empty;
		1 -> encryption_header: bytestring &length=12;
	};
	file_name		: bytestring &length=file_name_length;
	extra_field		: bytestring &length=extra_field_length;
	data			: bytestring &length=compressed_size;
	have_data_descriptor	: case ((flags & 0x08) > 0) of {
		true  -> data_descriptor: DataDescriptor;
		false -> no_dd          : empty;
	};
} &length=length;

type DataDescriptor = record {
	crc32             : uint16;
	compressed_size   : uint16;
	uncompressed_size : uint16;
} &byteorder=littleendian;

type ExtraDataHeader = record {
	length : uint32;
	data   : bytestring &length=length;
} &byteorder=littleendian;

type CentralDirectoryStructure = record {
	version_created		: uint16;
	version_needed		: uint16;
	flags			: uint16;
	compression_method	: uint16;
	last_modified_time	: uint16;
	last_modified_date	: uint16;
	crc32			: uint16;
	compressed_size		: uint32;
	uncompressed_size	: uint32;
	file_name_length	: uint16;
	extra_field_length	: uint16;
	file_comment_length	: uint16;
	disk_number_start	: uint16;
	internal_file_attrs	: uint16;
	external_file_attrs	: uint16;
	local_header_offset	: uint16;

	file_name		: bytestring &length=file_name_length;
	extra_field		: ExtraDataHeader &length=extra_field_length;
        file_comment		: bytestring &length=file_comment_length;
} &byteorder=littleendian;

type DigitalSignature = record {
	length : uint32;
	data   : bytestring &length=length;
} &byteorder=littleendian;

type EndOfCentralDirectoryStructure = record {
	disk_number			: uint16;
	central_dir_disk_number		: uint16;
	central_dir_entries_on_this_disk: uint16;
	central_dir_total_entries	: uint16;
	central_dir_size		: uint16;
	central_dir_offset		: uint32;
	file_comment_length		: uint16;
	file_comment			: bytestring &length=file_comment_length;
} &byteorder=littleendian;

