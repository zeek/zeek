#ifndef BRO_FD_SET_H
#define BRO_FD_SET_H

#include <set>
#include <sys/select.h>

namespace iosource {

/**
 * A container holding a set of file descriptors.
 */
class FD_Set {
public:

	/**
	 * Constructor.  The set is initially empty.
	 */
	FD_Set() : max(-1), fds()
		{ }

	/**
	 * Insert a file descriptor in to the set.
	 * @param fd the fd to insert in the set.
	 * @return false if fd was already in the set, else true.
	 */
	bool Insert(int fd)
		{
		if ( max < fd )
			max = fd;

		return fds.insert(fd).second;
		}

	/**
	 * Inserts all the file descriptors from another set in to this one.
	 * @param other a file descriptor set to merge in to this one.
	 */
	void Insert(const FD_Set& other)
		{
		for ( std::set<int>::const_iterator it = other.fds.begin();
		      it != other.fds.end(); ++it )
			Insert(*it);
		}

	/**
	 * Empties the set.
	 */
	void Clear()
		{ max = -1; fds.clear(); }

	/**
	 * Insert file descriptors in to a fd_set for use with select().
	 * @return the greatest file descriptor inserted.
	 */
	int Set(fd_set* set) const
		{
		for ( std::set<int>::const_iterator it = fds.begin(); it != fds.end();
		      ++it )
			FD_SET(*it, set);

		return max;
		}

	/**
	 * @return Whether a file descriptor belonging to this set is within the
	 *         fd_set arugment.
	 */
	bool Ready(fd_set* set) const
		{
		for ( std::set<int>::const_iterator it = fds.begin(); it != fds.end();
		      ++it )
			{
			if ( FD_ISSET(*it, set) )
				return true;
			}

		return false;
		}

	/**
	 * @return whether any file descriptors have been added to the set.
	 */
	bool Empty() const
		{
		return fds.empty();
		}

	/**
	 * @return the greatest file descriptor of all that have been added to the
	 * set, or -1 if the set is empty.
	 */
	int Max() const
		{
		return max;
		}

private:
	int max;
	std::set<int> fds;
};

} // namespace bro

#endif // BRO_FD_SET_H
