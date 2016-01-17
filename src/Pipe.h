// See the file "COPYING" in the main distribution directory for copyright.

#ifndef BRO_PIPE_H
#define BRO_PIPE_H

namespace bro {

class Pipe {
public:

	/**
	 * Create a pair of file descriptors via pipe(), or aborts if it cannot.
	 * @param flags0 file descriptor flags to set on read end of pipe.
	 * @param flags1 file descriptor flags to set on write end of pipe.
	 * @param status_flags0 descriptor status flags to set on read end of pipe.
	 * @param status_flags1 descriptor status flags to set on write end of pipe.
	 */
	Pipe(int flags0 = 0, int flags1 = 0, int status_flags0 = 0,
	     int status_flags1 = 0);

	/**
	  * Close the pair of file descriptors owned by the object.
	  */
	~Pipe();

	/**
	 * Make a copy of another Pipe object (file descriptors are dup'd).
	 */
	Pipe(const Pipe& other);

	/**
	 * Assign a Pipe object by closing file descriptors and duping those of
	 * the other.
	 */
	Pipe& operator=(const Pipe& other);

	/**
	 * @return the file descriptor associated with the read-end of the pipe.
	 */
	int ReadFD() const
		{ return fds[0]; }

	/**
	 * @return the file descriptor associated with the write-end of the pipe.
	 */
	int WriteFD() const
		{ return fds[1]; }

private:
	int fds[2];
	int flags[2];
};

} // namespace bro

#endif // BRO_PIPE_H
