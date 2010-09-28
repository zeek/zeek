#include "pac_id.h"
#include "pac_primitive.h"
#include "pac_output.h"

#include "pac_embedded.h"

EmbeddedCodeSegment::EmbeddedCodeSegment(const string &s)
	: s_(s), primitive_(0)
	{
	}

EmbeddedCodeSegment::EmbeddedCodeSegment(PacPrimitive *primitive)
	: s_(""), primitive_(primitive)
	{
	}

EmbeddedCodeSegment::~EmbeddedCodeSegment()
	{
	delete primitive_;
	}

string EmbeddedCodeSegment::ToCode(Env *env)
	{
	if ( primitive_ &&  s_.empty() )
		s_ = primitive_->ToCode(env);
	return s_;
	}

EmbeddedCode::EmbeddedCode()
	{
	segments_ = new EmbeddedCodeSegmentList();
	}

EmbeddedCode::~EmbeddedCode()
	{
	delete_list(EmbeddedCodeSegmentList, segments_);
	}

void EmbeddedCode::Append(int atom)
	{
	current_segment_ += static_cast<char>(atom);
	}

void EmbeddedCode::Append(const char *str)
	{
	current_segment_ += str;
	}

void EmbeddedCode::Append(PacPrimitive *primitive)
	{
	if ( ! current_segment_.empty() )
		{
		segments_->push_back(new EmbeddedCodeSegment(current_segment_));
		current_segment_ = "";
		}
	segments_->push_back(new EmbeddedCodeSegment(primitive));
	}

void EmbeddedCode::GenCode(Output *out, Env *env)
	{
	if ( ! current_segment_.empty() )
		{
		segments_->push_back(new EmbeddedCodeSegment(current_segment_));
		current_segment_ = "";
		}

	// TODO: return to the generated file after embedded code
	// out->print("#line %d \"%s\"\n", line_num, filename.c_str());

	// Allow use of RValue for undefined ID, in which case the
	// ID's name is used as its RValue
	env->set_allow_undefined_id(true);

	foreach(i, EmbeddedCodeSegmentList, segments_)
		{
		EmbeddedCodeSegment *segment = *i;
		out->print("%s", segment->ToCode(env).c_str());
		}

	env->set_allow_undefined_id(false);
	out->print("\n");
	}
