// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "Entropy.h"
#include "util.h"
#include "Event.h"
#include "file_analysis/Manager.h"

using namespace file_analysis;

Entropy::Entropy(IntrusivePtr<RecordVal> args, File* file)
    : file_analysis::Analyzer(file_mgr->GetComponentTag("ENTROPY"),
                              std::move(args), file)
	{
	//entropy->Init();
	entropy = new EntropyVal;
	fed = false;
	}

Entropy::~Entropy()
	{
	Unref(entropy);
	}

file_analysis::Analyzer* Entropy::Instantiate(IntrusivePtr<RecordVal> args,
                                              File* file)
	{
	return new Entropy(std::move(args), file);
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

	static auto entropy_test_result = zeek::id::find_type<RecordType>("entropy_test_result");
	auto ent_result = make_intrusive<RecordVal>(entropy_test_result);
	ent_result->Assign<DoubleVal>(0, ent);
	ent_result->Assign<DoubleVal>(1, chisq);
	ent_result->Assign<DoubleVal>(2, mean);
	ent_result->Assign<DoubleVal>(3, montepi);
	ent_result->Assign<DoubleVal>(4, scc);

	mgr.Enqueue(file_entropy,
		GetFile()->ToVal(),
		std::move(ent_result)
	);
	}
