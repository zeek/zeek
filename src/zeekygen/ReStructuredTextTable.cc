// See the file "COPYING" in the main distribution directory for copyright.

#include "ReStructuredTextTable.h"

#include <assert.h>

using namespace std;
using namespace zeekygen;

ReStructuredTextTable::ReStructuredTextTable(size_t arg_num_cols)
	: num_cols(arg_num_cols), rows(), longest_row_in_column()
	{
	for ( size_t i = 0; i < num_cols; ++i )
		longest_row_in_column.push_back(1);
	}

void ReStructuredTextTable::AddRow(const vector<string>& new_row)
	{
	assert(new_row.size() == num_cols);
	rows.push_back(new_row);

	for ( size_t i = 0; i < new_row.size(); ++i )
		if ( new_row[i].size() > longest_row_in_column[i] )
			longest_row_in_column[i] = new_row[i].size();
	}

string ReStructuredTextTable::MakeBorder(const vector<size_t>& col_sizes,
                                         char border)
	{
	string rval;

	for ( size_t i = 0; i < col_sizes.size(); ++i )
		{
		if ( i > 0 )
			rval += " ";

		rval += string(col_sizes[i], border);
		}

	rval += "\n";
	return rval;
	}

string ReStructuredTextTable::AsString(char border) const
	{
	string rval = MakeBorder(longest_row_in_column, border);

	for ( size_t row = 0; row < rows.size(); ++row )
		{
		for ( size_t col = 0; col < num_cols; ++col )
			{
			if ( col > 0 )
				{
				size_t last = rows[row][col - 1].size();
				size_t longest = longest_row_in_column[col - 1];
				size_t whitespace = longest - last + 1;
				rval += string(whitespace, ' ');
				}

			rval += rows[row][col];
			}

		rval += "\n";
		}

	rval += MakeBorder(longest_row_in_column, border);
	return rval;
	}
