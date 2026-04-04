// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeekygen/ReStructuredTextTable.h"

#include <algorithm>
#include <cassert>
#include <ranges>

using namespace std;

namespace zeek::zeekygen::detail {

ReStructuredTextTable::ReStructuredTextTable(size_t arg_num_cols)
    : num_cols(arg_num_cols), rows(), longest_row_in_column() {
    for ( size_t i = 0; i < num_cols; ++i )
        longest_row_in_column.push_back(1);
}

void ReStructuredTextTable::AddRow(const vector<string>& new_row) {
    assert(new_row.size() == num_cols);
    rows.push_back(new_row);

    for ( size_t i = 0; i < new_row.size(); ++i )
        if ( new_row[i].size() > longest_row_in_column[i] )
            longest_row_in_column[i] = new_row[i].size();
}

string ReStructuredTextTable::MakeBorder(const vector<size_t>& col_sizes, char border) {
    string rval;

    for ( size_t i = 0; i < col_sizes.size(); ++i ) {
        if ( i > 0 )
            rval += " ";

        rval += string(col_sizes[i], border);
    }

    rval += "\n";
    return rval;
}

string ReStructuredTextTable::AsString(char border) const {
    string rval = MakeBorder(longest_row_in_column, border);

    for ( const auto& row : rows ) {
        bool row_is_empty = true;
        for ( const auto& cell : row ) {
            if ( ! cell.empty() ) {
                row_is_empty = false;
                break;
            }
        }

        if ( row_is_empty ) {
            rval += "\n";
            continue;
        }

        string row_str;
        for ( size_t col = 0; col < num_cols; ++col ) {
            if ( col > 0 ) {
                size_t last = row[col - 1].size();
                size_t longest = longest_row_in_column[col - 1];
                size_t whitespace = longest - last + 1;
                row_str += string(whitespace, ' ');
            }

            row_str += row[col];
        }

        // Pop off trailing spaces
        auto notspace = [](unsigned char c) { return ! std::isspace(c); };
        row_str.erase(std::ranges::find_if(std::ranges::reverse_view(row_str), notspace).base(), row_str.end());

        rval += row_str;
        rval += "\n";
    }

    rval += MakeBorder(longest_row_in_column, border);
    return rval;
}

} // namespace zeek::zeekygen::detail
