## Process this file with automake to produce Makefile.in

AM_YFLAGS = -d -t -v
AM_CPPFLAGS = -W -Wall -Wno-unused

noinst_PROGRAMS = binpac

binpac_SOURCES = \
	pac_scan.ll pac_parse.yy \
	pac_action.cc \
	pac_analyzer.cc \
	pac_array.cc \
	pac_attr.cc \
	pac_btype.cc \
	pac_case.cc \
	pac_conn.cc \
	pac_context.cc \
	pac_cstr.cc \
	pac_datadep.cc \
	pac_dataptr.cc \
	pac_dataunit.cc \
	pac_decl.cc \
	pac_embedded.cc \
	pac_enum.cc \
	pac_expr.cc \
	pac_exttype.cc \
	pac_field.cc \
	pac_flow.cc \
	pac_func.cc \
	pac_id.cc \
	pac_inputbuf.cc \
	pac_let.cc \
	pac_param.cc \
	pac_paramtype.cc \
	pac_primitive.cc \
	pac_record.cc \
	pac_redef.cc \
	pac_regex.cc \
	pac_state.cc \
	pac_strtype.cc \
	pac_type.cc \
	pac_typedecl.cc \
	pac_withinput.cc \
	pac_output.cc pac_utils.cc pac_exception.cc \
	pac_main.cc \
	pac_action.h pac_analyzer.h pac_array.h pac_attr.h pac_btype.h \
	pac_case.h pac_cclass.h pac_common.h pac_conn.h pac_context.h \
	pac_cstr.h pac_ctype.h pac_datadep.h pac_dataptr.h pac_dataunit.h \
	pac_dbg.h pac_decl-inl.h pac_decl.h pac_embedded.h pac_enum.h \
	pac_exception.h pac_expr.h pac_exttype.h pac_field.h pac_flow.h \
	pac_func.h pac_id.h pac_inputbuf.h pac_let.h pac_number.h \
	pac_output.h pac_param.h pac_paramtype.h pac_parse.h pac_primitive.h \
	pac_record.h pac_redef.h pac_regex.h pac_state.h pac_strtype.h \
	pac_type.h pac_typedecl.h pac_utils.h pac_varfield.h pac_withinput.h

EXTRA_DIST = pac_expr.def pac_type.def pac_externtype.def

DISTCLEANFILES = pac_parse.cc pac_parse.h pac_scan.cc y.output

# Manual rules below:

pac_scan.o:	pac_parse.h
