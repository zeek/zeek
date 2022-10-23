// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/SmithWaterman.h"

#include "zeek/zeek-config.h"

#include <algorithm>
#include <cctype>

#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/Var.h"
#include "zeek/util.h"

namespace zeek::detail
	{

Substring::Substring(const Substring& bst) : String((const String&)bst), _num(), _new(bst._new)
	{
	for ( const auto& align : bst._aligns )
		_aligns.push_back(align);
	}

const Substring& Substring::operator=(const Substring& bst)
	{
	String::operator=(bst);

	_aligns.clear();

	for ( const auto& align : bst._aligns )
		_aligns.push_back(align);

	_new = bst._new;

	return *this;
	}

void Substring::AddAlignment(const String* str, int index)
	{
	_aligns.push_back(BSSAlign(str, index));
	}

bool Substring::DoesCover(const Substring* bst) const
	{
	if ( _aligns.size() != bst->_aligns.size() )
		return false;

	auto it_bst = bst->_aligns.begin();

	for ( auto it = _aligns.begin(); it != _aligns.end(); ++it, ++it_bst )
		{
		const BSSAlign& a = *it;
		const BSSAlign& a_bst = *it_bst;

		if ( a.index > a_bst.index || a.index + Len() < a_bst.index + bst->Len() )
			return false;
		}

	return true;
	}

VectorVal* Substring::VecToPolicy(Vec* vec)
	{
	static auto sw_substring_type = id::find_type<RecordType>("sw_substring");
	static auto sw_align_type = id::find_type<RecordType>("sw_align");
	static auto sw_align_vec_type = id::find_type<VectorType>("sw_align_vec");
	static auto sw_substring_vec_type = id::find_type<VectorType>("sw_substring_vec");

	auto result = make_intrusive<VectorVal>(sw_substring_vec_type);

	if ( vec )
		{
		for ( size_t i = 0; i < vec->size(); ++i )
			{
			Substring* bst = (*vec)[i];

			auto st_val = make_intrusive<RecordVal>(sw_substring_type);
			st_val->Assign(0, new String(*bst));

			auto aligns = make_intrusive<VectorVal>(sw_align_vec_type);

			for ( unsigned int j = 0; j < bst->GetNumAlignments(); ++j )
				{
				const BSSAlign& align = (bst->GetAlignments())[j];

				auto align_val = make_intrusive<RecordVal>(sw_align_type);
				align_val->Assign(0, new String(*align.string));
				align_val->Assign(1, align.index);

				aligns->Assign(j, std::move(align_val));
				}

			st_val->Assign(1, std::move(aligns));
			st_val->Assign(2, bst->IsNewAlignment());
			result->Assign(i, std::move(st_val));
			}
		}

	return result.release();
	}

Substring::Vec* Substring::VecFromPolicy(VectorVal* vec)
	{
	Vec* result = new Vec();

	for ( unsigned int i = 0; i < vec->Size(); ++i )
		{
		auto v = vec->RecordValAt(i);
		if ( ! v )
			continue;

		const String* str = v->GetFieldAs<StringVal>(0);
		auto* substr = new Substring(*str);

		const VectorVal* aligns = v->GetFieldAs<VectorVal>(1);
		for ( unsigned int j = 1; j <= aligns->Size(); ++j )
			{
			const RecordVal* align = aligns->AsVectorVal()->RecordValAt(j);
			const String* str = align->GetFieldAs<StringVal>(0);
			int index = align->GetFieldAs<CountVal>(1);
			substr->AddAlignment(str, index);
			}

		bool new_alignment = v->GetFieldAs<BoolVal>(2);
		substr->MarkNewAlignment(new_alignment);

		result->push_back(substr);
		}

	return result;
	}

char* Substring::VecToString(Vec* vec)
	{
	std::string result("[");

	for ( const auto& ss : *vec )
		{
		result += ss->CheckString();
		result += ",";
		}

	result += "]";
	return strdup(result.c_str());
	}

String::IdxVec* Substring::GetOffsetsVec(const Vec* vec, unsigned int index)
	{
	String::IdxVec* result = new String::IdxVec();

	for ( const auto& bst : *vec )
		{
		if ( bst->_aligns.size() <= index )
			continue;

		const BSSAlign& align = bst->_aligns[index];
		int start = align.index;
		int end = start + bst->Len();

		result->push_back(start);
		result->push_back(end);
		}

	return result;
	}

bool SubstringCmp::operator()(const Substring* bst1, const Substring* bst2) const
	{
	if ( _index >= bst1->GetNumAlignments() || _index >= bst2->GetNumAlignments() )
		{
		reporter->Warning("SubstringCmp::operator(): invalid index for input strings.\n");
		return false;
		}

	if ( bst1->GetAlignments()[_index].index <= bst2->GetAlignments()[_index].index )
		return true;

	return false;
	}

// A node in Smith-Waterman's dynamic programming matrix.  Each node
// contains the byte it represents in the case of a match, the score
// at this point, and a pointer to the previous cell. Previous means
// one up and left in case of a match, or a jump somewhere above and
// left in case of a gap.
//
struct SWNode
	{
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
class SWNodeMatrix
	{
public:
	SWNodeMatrix(const String* s1, const String* s2)
		: _s1(s1), _s2(s2), _rows(s1->Len() + 1), _cols(s2->Len() + 1)
		{
		_nodes = new SWNode[_cols * _rows];
		memset(_nodes, 0, sizeof(SWNode) * _cols * _rows);
		}

	~SWNodeMatrix() { delete[] _nodes; }

	SWNode* operator()(int row, int col)
		{
		// Make sure access is in allowed range.
		if ( row < 0 || row >= _rows )
			return nullptr;
		if ( col < 0 || col >= _cols )
			return nullptr;

		return &(_nodes[row * _cols + col]);
		}

	const String* GetRowsString() const { return _s1; }
	const String* GetColsString() const { return _s2; }

	int GetHeight() const { return _rows; }
	int GetWidth() const { return _cols; }

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
	const String* _s1;
	const String* _s2;

	int _rows, _cols;
	SWNode* _nodes;
	};

// Returns the common subsequence starting from a given node.
// @result: vector holding results on return.
// @matrix: SW matrix.
// @node: starting node.
// @params: SW parameters.
//
static void sw_collect_single(Substring::Vec* result, SWNodeMatrix& matrix, SWNode* node,
                              SWParams& params)
	{
	std::string substring("");
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
				auto* bst = new Substring(substring);
				bst->AddAlignment(matrix.GetRowsString(), row - 1);
				bst->AddAlignment(matrix.GetColsString(), col - 1);
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
		auto* bst = new Substring(substring);
		bst->AddAlignment(matrix.GetRowsString(), row - 1);
		bst->AddAlignment(matrix.GetColsString(), col - 1);
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
static void sw_collect_multiple(Substring::Vec* result, SWNodeMatrix& matrix, SWParams& params)
	{
	std::vector<Substring::Vec*> als;

	for ( int i = matrix.GetHeight() - 1; i > 0; --i )
		{
		for ( int j = matrix.GetWidth() - 1; j > 0; --j )
			{
			SWNode* node = matrix(i, j);

			if ( ! (node->swn_byte_assigned && ! node->swn_visited) )
				continue;

			auto* new_al = new Substring::Vec();
			sw_collect_single(new_al, matrix, node, params);

			for ( auto& old_al : als )
				{
				if ( old_al == nullptr )
					continue;

				for ( const auto& old_ss : *old_al )
					{
					for ( const auto& new_ss : *new_al )
						{
						if ( old_ss->DoesCover(new_ss) )
							{
							util::delete_each(new_al);
							delete new_al;
							new_al = nullptr;
							goto end_loop;
							}

						if ( new_ss->DoesCover(old_ss) )
							{
							util::delete_each(old_al);
							delete old_al;
							old_al = nullptr;
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

	for ( const auto& al : als )
		{
		if ( al == nullptr )
			continue;

		for ( const auto& bst : *al )
			result->push_back(bst);

		delete al;
		}
	}

// The main Smith-Waterman algorithm.
//
Substring::Vec* smith_waterman(const String* s1, const String* s2, SWParams& params)
	{
	auto* result = new Substring::Vec();

	if ( ! s1 || s1->Len() < int(params._min_toklen) || ! s2 ||
	     s2->Len() < int(params._min_toklen) )
		return result;

	// Length of both strings, plus one because SW needs
	// an extra row and column.
	//
	int i, len1 = s1->Len() + 1;
	int j, len2 = s2->Len() + 1;

	int row = 0, col = 0;

	byte_vec string1 = s1->Bytes();
	byte_vec string2 = s2->Bytes();

	SWNodeMatrix matrix(s1, s2); // dynamic programming matrix.
	SWNode* node_max = nullptr; // pointer to the best score's node
	SWNode* node_br_max = nullptr; // pointer to lowest-right matching node

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
			SWNode* node_tl = matrix(i - 1, j - 1);
			SWNode* node_l = matrix(i, j - 1);
			SWNode* node_t = matrix(i - 1, j);

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
			if ( string1[i - 1] == string2[j - 1] )
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
				current->swn_byte = string1[i - 1];
				current->swn_byte_assigned = true;
				}

			// Pick the score among the neighbours that is now highest.
			// This is the core of Smith-Waterman.
			//
			if ( current->swn_byte_assigned )
				current->swn_score = score_tl;
			else
				current->swn_score = std::max(std::max(score_t, score_l), score_tl);

			// Establish predecessor chain according to neighbor
			// with best score.
			//
			if ( current->swn_score == score_tl && current->swn_byte_assigned )
				{
				// If we had matched bytes (*and* it's the
				// best neighbor), mark the node accordingly
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
			// printf("%.5i ", current->swn_score);
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
		sort(result->begin(), result->end(), SubstringCmp(0));
	else
		sort(result->begin(), result->end(), SubstringCmp(1));

	return result;
	}

	} // namespace zeek::detail
