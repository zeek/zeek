// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "Entropy.h"
#include "util.h"
#include "Event.h"
#include "file_analysis/Manager.h"

using namespace file_analysis;

Entropy::Entropy(RecordVal* args, File* file)
    : file_analysis::Analyzer(file_mgr->GetComponentTag("ENTROPY"), args, file)
	{
	//entropy->Init();
	entropy = new EntropyVal;
	fed = false;
	}

Entropy::~Entropy()
	{
	Unref(entropy);
	}

file_analysis::Analyzer* Entropy::Instantiate(RecordVal* args, File* file)
	{
	return new Entropy(args, file);
	}

bool Entropy::DeliverStream(const u_char* data, uint64_t len)
	{
	if ( ! fed )
		fed = len > 0;

	entropy->Feed(data, len);
	return true;
	}

bool Entropy::EndOfFile()
	{
	Finalize();
	return false;
	}

bool Entropy::Undelivered(uint64_t offset, uint64_t len)
	{
	return false;
	}

void Entropy::Finalize()
	{
	//if ( ! entropy->IsValid() || ! fed )
	if ( ! fed )
		return;

	if ( ! file_entropy )
		return;

	double montepi, scc, ent, mean, chisq;
	montepi = scc = ent = mean = chisq = 0.0;
	entropy->Get(&ent, &chisq, &mean, &montepi, &scc);

	static auto entropy_test_result = zeek::lookup_type<RecordType>("entropy_test_result");
	auto ent_result = make_intrusive<RecordVal>(entropy_test_result);
	ent_result->Assign(0, make_intrusive<Val>(ent,     TYPE_DOUBLE));
	ent_result->Assign(1, make_intrusive<Val>(chisq,   TYPE_DOUBLE));
	ent_result->Assign(2, make_intrusive<Val>(mean,    TYPE_DOUBLE));
	ent_result->Assign(3, make_intrusive<Val>(montepi, TYPE_DOUBLE));
	ent_result->Assign(4, make_intrusive<Val>(scc,     TYPE_DOUBLE));

	mgr.Enqueue(file_entropy,
		IntrusivePtr{NewRef{}, GetFile()->GetVal()},
		std::move(ent_result)
	);
	}
