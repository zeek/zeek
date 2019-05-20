// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "EquivClass.h"

EquivClass::EquivClass(int arg_size)
	{
	size = arg_size;
	fwd = new int[size];
	bck = new int[size];
	equiv_class = new int[size];
	rep = new int[size];
	ccl_flags = 0;
	num_ecs = 0;

	ec_nil = no_class = no_rep = size + 1;

	bck[0] = ec_nil;
	fwd[size - 1] = ec_nil;

	for ( int i = 0; i < size; ++i )
		{
		if ( i > 0 )
			{
			fwd[i - 1] = i;
			bck[i] = i - 1;
			}

		equiv_class[i] = no_class;
		rep[i] = no_rep;
		}
	}

EquivClass::~EquivClass()
	{
	delete [] fwd;
	delete [] bck;
	delete [] equiv_class;
	delete [] rep;
	delete [] ccl_flags;
	}

void EquivClass::ConvertCCL(CCL* ccl)
	{
	// For each character in the class, add the character's
	// equivalence class to the new "character" class we are
	// creating.  Thus when we are all done, the character class
	// will really consist of collections of equivalence classes
	// instead of collections of characters.

	int_list* c_syms = ccl->Syms();
	int_list* new_syms = new int_list;

	for ( int i = 0; i < c_syms->length(); ++i )
		{
		int sym = (*c_syms)[i];
		if ( IsRep(sym) )
			new_syms->append(SymEquivClass(sym));
		}

	ccl->ReplaceSyms(new_syms);
	}

int EquivClass::BuildECs()
	{
	// Create equivalence class numbers.  If bck[x] is nil,
	// then x is the representative of its equivalence class.

	for ( int i = 0; i < size; ++i )
		if ( bck[i] == ec_nil )
			{
			equiv_class[i] = num_ecs++;
			rep[i] = i;
			for ( int j = fwd[i]; j != ec_nil; j = fwd[j] )
				{
				equiv_class[j] = equiv_class[i];
				rep[j] = i;
				}
			}

	return num_ecs;
	}

void EquivClass::CCL_Use(CCL* ccl)
	{
	// Note that it doesn't matter whether or not the character class is
	// negated.  The same results will be obtained in either case.

	if ( ! ccl_flags )
		{
		ccl_flags = new int[size];
		for ( int i = 0; i < size; ++i )
			ccl_flags[i] = 0;
		}

	int_list* csyms = ccl->Syms();
	for ( int i = 0; i < csyms->length(); /* no increment */ )
		{
		int sym = (*csyms)[i];

		int old_ec = bck[sym];
		int new_ec = sym;

		int j = i + 1;

		for ( int k = fwd[sym]; k && k < size; k = fwd[k] )
			{ // look for the symbol in the character class
			for ( ; j < csyms->length(); ++j )
				{
				if ( (*csyms)[j] > k )
					// Since the character class is sorted,
					// we can stop.
					break;

				if ( (*csyms)[j] == k && ! ccl_flags[j] )
					{
					// We found an old companion of sym
					// in the ccl.  Link it into the new
					// equivalence class and flag it as
					// having been processed.
					bck[k] = new_ec;
					fwd[new_ec] = k;
					new_ec = k;

					// Set flag so we don't reprocess.
					ccl_flags[j] = 1;

					// Get next equivalence class member.
					break;
					}
				}

			if ( j < csyms->length() && (*csyms)[j] == k )
				// We broke out of the above loop by finding
				// an old companion - go to the next symbol.
				continue;

			// Symbol isn't in character class.  Put it in the old
			// equivalence class.
			bck[k] = old_ec;
			if ( old_ec != ec_nil )
				fwd[old_ec] = k;

			old_ec = k;
			}

		if ( bck[sym] != ec_nil || old_ec != bck[sym] )
			{
			bck[sym] = ec_nil;
			fwd[old_ec] = ec_nil;
			}

		fwd[new_ec] = ec_nil;

		// Find next ccl member to process.
		for ( ++i; i < csyms->length() && ccl_flags[i]; ++i )
			// Reset "doesn't need processing" flag.
			ccl_flags[i] = 0;
		}
	}


void EquivClass::UniqueChar(int sym)
	{
	// If until now the character has been a proper subset of
	// an equivalence class, break it away to create a new ec.

	if ( fwd[sym] != ec_nil )
		bck[fwd[sym]] = bck[sym];

	if ( bck[sym] != ec_nil )
		fwd[bck[sym]] = fwd[sym];

	fwd[sym] = ec_nil;
	bck[sym] = ec_nil;
	}

void EquivClass::Dump(FILE* f)
	{
	fprintf(f, "%d symbols in EC yielded %d ecs\n", size, num_ecs);
	for ( int i = 0; i < size; ++i )
		if ( SymEquivClass(i) != 0 )	// skip usually huge default ec
			fprintf(f, "map %d ('%c') -> %d\n", i, i, SymEquivClass(i));
	}

int EquivClass::Size() const
	{
	return padded_sizeof(*this) + pad_size(sizeof(int) * size * (ccl_flags ? 5 : 4));
	}
