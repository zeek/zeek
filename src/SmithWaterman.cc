// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include <algorithm>
#include <ctype.h>

#include "SmithWaterman.h"
#include "Var.h"
#include "util.h"
#include "Reporter.h"

BroSubstring::BroSubstring(const BroSubstring& bst)
: BroString((const BroString&) bst), _num(), _new(bst._new)
	{
	for ( BSSAlignVecCIt it = bst._aligns.begin(); it != bst._aligns.end(); ++it )
		_aligns.push_back(*it);
	}

const BroSubstring& BroSubstring::operator=(const BroSubstring& bst)
	{
	BroString::operator=(bst);

	_aligns.clear();

	for ( BSSAlignVecCIt it = bst._aligns.begin(); it != bst._aligns.end(); ++it )
		_aligns.push_back(*it);

	_new = bst._new;

	return *this;
	}

void BroSubstring::AddAlignment(const BroString* str, int index)
	{
	_aligns.push_back(BSSAlign(str, index));
	}

bool BroSubstring::DoesCover(const BroSubstring* bst) const
	{
	if ( _aligns.size() != bst->_aligns.size() )
		return false;

	BSSAlignVecCIt it_bst = bst->_aligns.begin();

	for ( BSSAlignVecCIt it = _aligns.begin(); it != _aligns.end(); ++it, ++it_bst )
		{
		const BSSAlign& a = *it;
		const BSSAlign& a_bst = *it_bst;

		if (a.index > a_bst.index || a.index + Len() < a_bst.index + bst->Len())
			return false;
		}

	return true;
	}

VectorVal* BroSubstring::VecToPolicy(Vec* vec)
	{
	RecordType* sw_substring_type =
		internal_type("sw_substring")->AsRecordType();
	if ( ! sw_substring_type )
		return 0;

	RecordType* sw_align_type =
		internal_type("sw_align")->AsRecordType();
	if ( ! sw_align_type )
		return 0;

	VectorType* sw_align_vec_type =
		internal_type("sw_align_vec")->AsVectorType();
	if ( ! sw_align_vec_type )
		return 0;

	VectorVal* result =
		new VectorVal(internal_type("sw_substring_vec")->AsVectorType());
	if ( ! result )
		return 0;

	if ( vec )
		{
		for ( unsigned int i = 0; i < vec->size(); ++i )
			{
			BroSubstring* bst = (*vec)[i];

			RecordVal* st_val = new RecordVal(sw_substring_type);
			st_val->Assign(0, new StringVal(new BroString(*bst)));

			VectorVal* aligns = new VectorVal(sw_align_vec_type);

			for ( unsigned int j = 0; j < bst->GetNumAlignments(); ++j )
				{
				const BSSAlign& align = (bst->GetAlignments())[j];

				RecordVal* align_val = new RecordVal(sw_align_type);
				align_val->Assign(0, new StringVal(new BroString(*align.string)));
				align_val->Assign(1, val_mgr->GetCount(align.index));

				aligns->Assign(j+1, align_val);
				}

			st_val->Assign(1, aligns);
			st_val->Assign(2, val_mgr->GetBool(bst->IsNewAlignment()));
			result->Assign(i+1, st_val);
			}
		}

	return result;
	}

BroSubstring::Vec* BroSubstring::VecFromPolicy(VectorVal* vec)
	{
	Vec* result = new Vec();

	// VectorVals start at index 1!
	for ( unsigned int i = 1; i <= vec->Size(); ++i )
		{
		Val* v = vec->Lookup(i);	// get the RecordVal
		if ( ! v )
			continue;

		const BroString* str = v->AsRecordVal()->Lookup(0)->AsString();
		BroSubstring* substr = new BroSubstring(*str);

		const VectorVal* aligns = v->AsRecordVal()->Lookup(1)->AsVectorVal();
		for ( unsigned int j = 1; j <= aligns->Size(); ++j )
			{
			const RecordVal* align = aligns->AsVectorVal()->Lookup(j)->AsRecordVal();
			const BroString* str = align->Lookup(0)->AsString();
			int index = align->Lookup(1)->AsCount();
			substr->AddAlignment(str, index);
			}

		bool new_alignment = v->AsRecordVal()->Lookup(2)->AsBool();
		substr->MarkNewAlignment(new_alignment);

		result->push_back(substr);
		}

	return result;
	}

char* BroSubstring::VecToString(Vec* vec)
	{
	string result("[");

	for ( BroSubstring::VecIt it = vec->begin(); it != vec->end(); ++it )
		{
		result += (*it)->CheckString();
		result += ",";
		}

	result += "]";
	return strdup(result.c_str());
	}

BroString::IdxVec* BroSubstring::GetOffsetsVec(const Vec* vec, unsigned int index)
	{
	BroString::IdxVec* result = new BroString::IdxVec();

	for ( VecCIt it = vec->begin(); it != vec->end(); ++it )
		{
		int start, end;
		const BroSubstring* bst = (*it);

		if ( bst->_aligns.size() <= index )
			continue;

		const BSSAlign& align = bst->_aligns[index];
		start = align.index;
		end = start + bst->Len();

		result->push_back(start);
		result->push_back(end);
		}

	return result;
	}


bool BroSubstringCmp::operator()(const BroSubstring* bst1,
				 const BroSubstring* bst2) const
	{
	if ( _index >= bst1->GetNumAlignments() ||
	     _index >= bst2->GetNumAlignments() )
		{
		reporter->Warning("BroSubstringCmp::operator(): invalid index for input strings.\n");
		return false;
		}

	if ( bst1->GetAlignments()[_index].index <=
	     bst2->GetAlignments()[_index].index )
		return true;

	return false;
	}

// A node in Smith-Waterman's dynamic programming matrix.  Each node
// contains the byte it represents in the case of a match, the score
// at this point, and a pointer to the previous cell. Previous means
// one up and left in case of a match, or a jump somewhere above and
// left in case of a gap.
//
struct SWNode {
	// ID field for the cell, for debugging purposes.
	int id;

	u_char swn_byte;
	bool swn_byte_assigned;
	bool swn_visited;

	// The score in this cell. The cell with the globally best score
	// marks the end of the alignment.
	int swn_score;

	// Pointer to previous match, walking back yields subsequence.
	SWNode* swn_prev;
};

// A matrix of Smith-Waterman nodes.
//
class SWNodeMatrix {
public:
	SWNodeMatrix(const BroString* s1, const BroString* s2)
	: _s1(s1), _s2(s2), _rows(s1->Len() + 1), _cols(s2->Len() + 1)
		{
		_nodes = new SWNode[_cols * _rows];
		memset(_nodes, 0, sizeof(SWNode) * _cols * _rows);
		}

	~SWNodeMatrix()	{ delete [] _nodes; }

	SWNode* operator()(int row, int col)
		{
		// Make sure access is in allowed range.
		if ( row < 0 || row >= _rows )
			return 0;
		if ( col < 0 || col >= _cols )
			return 0;

		return &(_nodes[row * _cols + col]);
		}

	const BroString* GetRowsString() const	{ return _s1; }
	const BroString* GetColsString() const	{ return _s2; }

	int GetHeight() const	{ return _rows; }
	int GetWidth() const	{ return _cols; }

	// Quick helper function that calculates the coordinates of a
	// node in the matrix via pointer arithmetic.
	//
	void GetNodeIndices(SWNode* node, int& row, int& col)
		{
		SWNode* base = &_nodes[0];
		int offset = (node - base);
		col = (offset % _cols);
		row = (offset / _cols);
		}

private:
	const BroString* _s1;
	const BroString* _s2;

	int _rows, _cols;
	SWNode* _nodes;
};

// Returns the common subsequence starting from a given node.
// @result: vector holding results on return.
// @matrix: SW matrix.
// @node: starting node.
// @params: SW parameters.
//
static void sw_collect_single(BroSubstring::Vec* result, SWNodeMatrix& matrix,
			      SWNode* node, SWParams& params)
	{
	string substring("");
	int row = 0, col = 0;

	while ( node )
		{
//		printf("NODE: %i\n", node->id);
		node->swn_visited = true;

		// Once we hit a gap, terminate the string and prepend
		// it to our result vector, IF it has at least the length
		// requested through the params._min_toklen parameter.
		//
		if ( node->swn_byte_assigned )
			{
			matrix.GetNodeIndices(node, row, col);
			substring += node->swn_byte;
//			printf("SUBSTRING: %s\n", substring.c_str());
			}
		else
			{
//			printf("GAP\n");
			if ( substring.size() >= params._min_toklen )
				{
				reverse(substring.begin(), substring.end());
				BroSubstring* bst = new BroSubstring(substring);
				bst->AddAlignment(matrix.GetRowsString(), row-1);
				bst->AddAlignment(matrix.GetColsString(), col-1);
				result->push_back(bst);
				}

			substring = "";
			}

		node = node->swn_prev;
		}

	// Anything left over now is the first string of an alignment and is
	// manually added and marked as the beginning of a new alignment.
	//
	if ( substring.size() > 0 )
		{
		reverse(substring.begin(), substring.end());
		BroSubstring* bst = new BroSubstring(substring);
		bst->AddAlignment(matrix.GetRowsString(), row-1);
		bst->AddAlignment(matrix.GetColsString(), col-1);
		result->push_back(bst);
		}

	if ( result->size() > 0 )
		result->back()->MarkNewAlignment(true);
	}

// Returns repeated common-subsequence alignments.
// @result: vector holding results on return.
// @matrix: SW matrix.
// @params: SW parameters.
//
// The approach taken is to essentially follow back from all starting points of
// common subsequences while tracking which nodes were visited earlier and which
// substrings are redundant (i.e., fully covered by a larger common substring).
//
static void sw_collect_multiple(BroSubstring::Vec* result,
				SWNodeMatrix& matrix, SWParams& params)
	{
	vector<BroSubstring::Vec*> als;

	for ( int i = matrix.GetHeight() - 1; i > 0; --i )
		{
		for ( int j = matrix.GetWidth() - 1; j > 0; --j )
			{
			SWNode* node = matrix(i, j);

			if ( ! (node->swn_byte_assigned && ! node->swn_visited) )
				continue;

			BroSubstring::Vec* new_al = new BroSubstring::Vec();
			sw_collect_single(new_al, matrix, node, params);

			for ( vector<BroSubstring::Vec*>::iterator it = als.begin();
			      it != als.end(); ++it )
				{
				BroSubstring::Vec* old_al = *it;

				if ( old_al == 0 )
					continue;

				for ( BroSubstring::VecIt it2 = old_al->begin();
				      it2 != old_al->end(); ++it2 )
					{
					for ( BroSubstring::VecIt it3 = new_al->begin();
					      it3 != new_al->end(); ++it3 )
						{
						if ( (*it2)->DoesCover(*it3) )
							{
							delete_each(new_al);
							delete new_al;
							new_al = 0;
							goto end_loop;
							}

						if ( (*it3)->DoesCover(*it2) )
							{
							delete_each(old_al);
							delete old_al;
							*it = 0;
							goto end_loop;
							}
						}
					}
				}

end_loop:
			if ( new_al )
				als.push_back(new_al);
			}
		}

	for ( vector<BroSubstring::Vec*>::iterator it = als.begin();
	      it != als.end(); ++it )
		{
		BroSubstring::Vec* al = *it;

		if ( al == 0 )
			continue;

		for ( BroSubstring::VecIt it2 = al->begin();
		      it2 != al->end(); ++it2 )
			result->push_back(*it2);

		delete al;
		}
	}

// The main Smith-Waterman algorithm.
//
BroSubstring::Vec* smith_waterman(const BroString* s1, const BroString* s2,
					SWParams& params)
	{
	BroSubstring::Vec* result = new BroSubstring::Vec();

	if ( ! s1 || s1->Len() < int(params._min_toklen) ||
	     ! s2 || s2->Len() < int(params._min_toklen) )
		return result;

	// Length of both strings, plus one because SW needs
	// an extra row and column.
	//
	int i, len1 = s1->Len() + 1;
	int j, len2 = s2->Len() + 1;

	int row = 0, col = 0;

	byte_vec string1 = s1->Bytes();
	byte_vec string2 = s2->Bytes();

	SWNodeMatrix matrix(s1, s2);	// dynamic programming matrix.
	SWNode* node_max = 0;	// pointer to the best score's node
	SWNode* node_br_max = 0;	// pointer to lowest-right matching node

	// The highest score in the matrix, globally.  We initialize to 1
	// because we are only interested in real scores (initializing to
	// -infty would mean 0 is larger, and would complicate the link
	// structure in the matrix).
	//
	int matrix_max = 1;
	int br_max_r = 0;
	int br_max_b = 0;


	// Matrix initialization ----------------------------------------------

	// Assign IDs to each cell -- this is only for debugging purposes
	// and can go later.

	int counter = 1;

	for ( i = 1; i < len1; ++i )
		for ( j = 1; j < len2; ++j )
			matrix(i, j)->id = counter++;

	// Subsequence calculation --------------------------------------------

	for ( i = 1; i < len1; ++i )
		{
		for ( j = 1; j < len2; ++j )
			{
			// Current node, top/left neighbours.
			//
			SWNode* current = matrix(i, j);
			SWNode* node_tl = matrix(i-1, j-1);
			SWNode* node_l  = matrix(i, j-1);
			SWNode* node_t  = matrix(i-1, j);

			// Scores of neighbouring nodes.
			//
			int score_t = node_t->swn_score;
			int score_l = node_l->swn_score;
			int score_tl = node_tl->swn_score;

			// If strings at current indices match, assign new
			// score to current node.  Minus-one adjustments
			// are necessary since matrix has one extra
			// row + column.
			//
			if ( string1[i-1] == string2[j-1] )
				{
				// We have a match: improve previous score.
				//
				score_tl += 1;

				// If we're continuing a chain of matches, rate
				// higher.  This favours longer consecutive
				// substrings.
				//
				if ( node_tl->swn_byte_assigned )
					score_tl += 99;

				// Store the byte we've matched in the node for
				// easier access.
				//
				current->swn_byte = string1[i-1];
				current->swn_byte_assigned = true;
				}

			// Pick the score among the neighbours that is now highest.
			// This is the core of Smith-Waterman.
			//
			if ( current->swn_byte_assigned )
				current->swn_score = score_tl;
			else
				current->swn_score = max(max(score_t, score_l), score_tl);

			// Establish predecessor chain according to neighbor
			// with best score.
			//
			if ( current->swn_score == score_tl &&
			     current->swn_byte_assigned )
				{
				// If we had matched bytes (*and* it's the
				// best neighbor), marke the node accordingly
				//
				if ( i >= br_max_b && j >= br_max_r )
					{
					node_br_max = current;
					br_max_b = i;
					br_max_r = j;
					}

				current->swn_prev = node_tl;
				}
			else if ( current->swn_score == score_t )
				current->swn_prev = node_t;
			else
				current->swn_prev = node_l;

			// Check if we have a new global maximum -- we
			// specifically track the node that is the global
			// maximum so we now from where to backtrack at
			// the end of the matrix iteration.
			//
			if ( current->swn_score > matrix_max )
				{
				node_max = current;
				matrix_max = current->swn_score;
				}

#if 0
			printf("%4i/%.5i%c/%.5i[%c%c] ",
				current->swn_score,
		 		current->id,
				current->swn_byte_assigned ? '*' : ' ',
		 		current->swn_prev ? current->swn_prev->id : 0,
			       string1[i-1], string2[j-1]);
#endif
			//printf("%.5i ", current->swn_score); 
			}

#if 0
		printf("\n");
#endif
		}

	// Result generation.

	// How we do this depends on the mode we operate in.  In SW_SINGLE, we
	// follow the path from the best node until there is no predecessor
	// (that is, when we hit a node in row 0), and stop.  In SW_MULTIPLE,
	// we collect all non-redundant common subsequences.

	if ( params._sw_variant == SW_MULTIPLE )
		sw_collect_multiple(result, matrix, params);
	else
		sw_collect_single(result, matrix, node_max, params);

	if ( len1 > len2 )
		sort(result->begin(), result->end(), BroSubstringCmp(0));
	else
		sort(result->begin(), result->end(), BroSubstringCmp(1));

	return result;
	}
