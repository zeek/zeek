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

bool Entropy::DeliverStream(const u_char* data, uint64 len)
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

bool Entropy::Undelivered(uint64 offset, uint64 len)
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

	RecordVal* ent_result = new RecordVal(entropy_test_result);
	ent_result->Assign(0, new Val(ent,     TYPE_DOUBLE));
	ent_result->Assign(1, new Val(chisq,   TYPE_DOUBLE));
	ent_result->Assign(2, new Val(mean,    TYPE_DOUBLE));
	ent_result->Assign(3, new Val(montepi, TYPE_DOUBLE));
	ent_result->Assign(4, new Val(scc,     TYPE_DOUBLE));

	mgr.QueueEventFast(file_entropy, {
		GetFile()->GetVal()->Ref(),
		ent_result,
	});
	}
