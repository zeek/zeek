// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <vector>
#include <string>

namespace zeekygen {

/**
 * A reST table with arbitrary number of columns.
 */
class ReStructuredTextTable {
public:

	/**
	 * Create the reST table object.
	 * @param arg_num_cols The number of columns in the table.
	 */
	explicit ReStructuredTextTable(size_t arg_num_cols);

	/**
	 * Add a new content row to the table.
	 * @param new_row A vector with one element for each column in the table.
	 */
	void AddRow(const std::vector<std::string>& new_row);

	/**
	 * @param col_sizes Vector of column sizes (width in number of characters).
	 * @param border Character to use for the border.
	 * @return A border sized appropriated for the table with columns of sizes
	 * denoted by \a col_sizes.
	 */
	static std::string MakeBorder(const std::vector<size_t>& col_sizes,
	                              char border);

	/**
	 * @param border Character to use for the border.
	 * @return the reST representation of the table and its content.
	 */
	std::string AsString(char border) const;

private:

	size_t num_cols;
	std::vector<std::vector<std::string> > rows;
	std::vector<size_t> longest_row_in_column;
};

} // namespace zeekygen
