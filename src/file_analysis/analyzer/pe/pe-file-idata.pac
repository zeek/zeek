## Support for parsing the .idata section

type import_directory = record {
	rva_import_lookup_table : uint32;
	time_date_stamp         : uint32;
	forwarder_chain         : uint32;
	rva_module_name         : uint32;
	rva_import_addr_table   : uint32;
} &let {
	is_null: bool = rva_module_name == 0;
	proc: bool = $context.connection.proc_image_import_directory(this);
} &length=20;

type import_lookup_attrs(pe32_format: uint8) = record {
	is_pe32_plus: case pe32_format of {
		PE32_PLUS -> attrs_64: uint64;
		default   -> attrs_32: uint32;
	};
} &let {
	import_by_ordinal: bool = (pe32_format == PE32_PLUS) ? (attrs_64 & 0x8000000000000000) > 1: (attrs_32 & 0x80000000) > 1;
	attrs: uint64 = (pe32_format == PE32_PLUS) ? attrs_64 : attrs_32;
	ordinal: uint16 = attrs & 0xff;
	hint_rva: uint32 = attrs & 0xffff;
	proc9000: bool = $context.connection.proc_import_lookup_attrs(this);
} &length=(pe32_format == PE32_PLUS ? 8 : 4);

type import_lookup_table = record {
	attrs: import_lookup_attrs($context.connection.get_pe32_format())[] &until($element.attrs == 0);
} &let {
	proc: bool = $context.connection.proc_import_lookup_table(this);
};

type import_entry(is_module: bool, pad_align: uint8) = record {
	pad: bytestring &length=pad_align;
	has_index: case is_module of {
		true  -> null: empty;
		false -> index: uint16;
	};
	name: null_terminated_string;
} &let {
	proc_align: bool = $context.connection.proc_import_hint(name, is_module);
};

type idata = record {
	directory_table : import_directory[] &until $element.is_null;
	lookup_tables   : import_lookup_table[] &until $context.connection.get_num_imports() <= 0;
	hint_table	: import_entry($context.connection.get_next_hint_type(), $context.connection.get_next_hint_align())[] &until($context.connection.imports_done());
};

refine typeattr RVAS += &let {
	proc_import_table: bool = $context.connection.proc_idata_rva(rvas[1]) &if (num > 1);
};

refine connection MockConnection += {
	%member{
		uint8 num_imports_;        // How many import tables will we have?

		uint32 import_table_rva_;  // Used for finding the right section
		uint32 import_table_va_;
		uint32 import_table_len_;

		// We need to track the number of imports for each, to
		// know when we've parsed them all.
		vector<uint32> imports_per_module_;

		// These are to determine the alignment of the import hints
		uint32 next_hint_index_;
		uint8 next_hint_align_;
		bool next_hint_is_module_;

		// Track the module name, so we know what each import's for
		bytestring module_name_;
	%}

	%init{
		// It ends with a null import entry, so we'll set it to -1.
		num_imports_ = -1;

		// First hint is a module name.
		next_hint_is_module_ = true;
		next_hint_index_ = 0;
		next_hint_align_ = 0;

		module_name_ = bytestring();
	%}

	%cleanup{
		module_name_.free();
	%}

	# When we read the section header, store the relative virtual address and
	# size of the .idata section, so we know when we get there.
	function proc_idata_rva(r: RVA): bool
		%{
		import_table_rva_ = ${r.virtual_address};
		import_table_len_ = ${r.size};

		return true;
		%}

	# Each import directory means another module we're importing from.
	function proc_image_import_directory(i: import_directory): bool
		%{
		printf("Parsed import directory. name@%x, IAT@%x\n", ${i.rva_module_name}, ${i.rva_import_addr_table});
		num_imports_++;
		return true;
		%}

	# Store the number of functions imported in each module lookup table.
	function proc_import_lookup_table(t: import_lookup_table): bool
		%{
		--num_imports_;
		imports_per_module_.push_back(${t.attrs}->size());
		return true;
		%}

	function proc_import_lookup_attrs(t: import_lookup_attrs): bool
		%{
		printf("Parsed import lookup attrs. Hints @%x\n", ${t.hint_rva});
		return true;
		%}

	# We need to calculate the length of the next padding field
	function proc_import_hint(hint_name: bytestring, is_module: bool): bool
		%{
		printf("Parsed import hint\n");
		next_hint_align_ = ${hint_name}.length() % 2;
		if ( is_module && ${hint_name}.length() > 1 )
			{
			module_name_.clear();
			module_name_.init(${hint_name}.data(), ${hint_name}.length() - 1);
			}

		return true;
		%}

	# Functions have an index field, modules don't. Which one is this?
	function get_next_hint_type(): bool
		%{
		if ( next_hint_is_module_ )
			{
			next_hint_is_module_ = false;
			return true;
			}
		if ( --imports_per_module_[next_hint_index_] == 0)
			{
			++next_hint_index_;
			return true;
			}
		return false;
		%}

	function imports_done(): bool
		%{
		return next_hint_index_ == imports_per_module_.size();
		%}

	function get_module_name(): bytestring
		%{
		return module_name_;
		%}

	function get_import_table_addr(): uint32
		%{
		return import_table_va_ > 0 ? import_table_va_ : 0;
		%}

	function get_import_table_len(): uint32
		%{
		return import_table_va_ > 0 ? import_table_len_ : 0;
		%}

	function get_num_imports(): uint8
		%{
		return num_imports_;
		%}

	function get_next_hint_align(): uint8
		%{
		return next_hint_align_;
		%}

};
