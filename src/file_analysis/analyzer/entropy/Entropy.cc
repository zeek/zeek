// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "Entropy.h"
#include "util.h"
#include "Event.h"
#include "file_analysis/Manager.h"

namespace zeek::file_analysis::detail {

Entropy::Entropy(zeek::RecordValPtr args, zeek::file_analysis::File* file)
	: zeek::file_analysis::Analyzer(zeek::file_mgr->GetComponentTag("ENTROPY"),
	                                std::move(args), file)
	{
	entropy = new zeek::EntropyVal;
	fed = false;
	}

Entropy::~Entropy()
	{
	Unref(entropy);
	}

zeek::file_analysis::Analyzer* Entropy::Instantiate(zeek::RecordValPtr args,
                                                    zeek::file_analysis::File* file)
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
	if ( ! fed )
		return;

	if ( ! file_entropy )
		return;

	double montepi, scc, ent, mean, chisq;
	montepi = scc = ent = mean = chisq = 0.0;
	entropy->Get(&ent, &chisq, &mean, &montepi, &scc);

	static auto entropy_test_result = zeek::id::find_type<zeek::RecordType>("entropy_test_result");
	auto ent_result = zeek::make_intrusive<zeek::RecordVal>(entropy_test_result);
	ent_result->Assign<zeek::DoubleVal>(0, ent);
	ent_result->Assign<zeek::DoubleVal>(1, chisq);
	ent_result->Assign<zeek::DoubleVal>(2, mean);
	ent_result->Assign<zeek::DoubleVal>(3, montepi);
	ent_result->Assign<zeek::DoubleVal>(4, scc);

	zeek::event_mgr.Enqueue(file_entropy,
	                        GetFile()->ToVal(),
	                        std::move(ent_result)
	);
	}

} // namespace zeek::file_analysis::detail
