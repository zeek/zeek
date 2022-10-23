// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

namespace zeek::detail
	{

class Pipe
	{
public:
	/**
	 * Create a pair of file descriptors via pipe(), or aborts if it cannot.
	 * @param flags0 file descriptor flags to set on read end of pipe.
	 * @param flags1 file descriptor flags to set on write end of pipe.
	 * @param status_flags0 descriptor status flags to set on read end of pipe.
	 * @param status_flags1 descriptor status flags to set on write end of pipe.
	 * @param fds may be supplied to open an existing file descriptors rather
	 * than create ones from a new pipe.  Should point to memory containing
	 * two consecutive file descriptors, the "read" one and then the "write" one.
	 */
	explicit Pipe(int flags0 = 0, int flags1 = 0, int status_flags0 = 0, int status_flags1 = 0,
	              int* fds = nullptr);

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
	int ReadFD() const { return fds[0]; }

	/**
	 * @return the file descriptor associated with the write-end of the pipe.
	 */
	int WriteFD() const { return fds[1]; }

	/**
	 * Sets the given file descriptor flags for both the read and write end
	 * of the pipe.
	 */
	void SetFlags(int flags);

	/**
	 * Unsets the given file descriptor flags for both the read and write end
	 * of the pipe.
	 */
	void UnsetFlags(int flags);

private:
	int fds[2];
	int flags[2];
	int status_flags[2];
	};

/**
 * A pair of pipes that can be used for bi-directional IPC.
 */
class PipePair
	{
public:
	/**
	 * Create a pair of pipes
	 * @param flags  file descriptor flags to set on pipes
	 * @status_flags  descriptor status flags to set on pipes
	 * @fds  may be supplied to open existing file descriptors rather
	 * than create ones from a new pair of pipes.  Should point to memory
	 * containing four consecutive file descriptors, "read" end and "write" end
	 * of the first pipe followed by the "read" end and "write" end of the
	 * second pipe.
	 */
	PipePair(int flags, int status_flags, int* fds = nullptr);

	/**
	 * @return the pipe used for receiving input
	 */
	Pipe& In() { return pipes[swapped]; }

	/**
	 * @return the pipe used for sending output
	 */
	Pipe& Out() { return pipes[! swapped]; }

	/**
	 * @return the pipe used for receiving input
	 */
	const Pipe& In() const { return pipes[swapped]; }

	/**
	 * @return the pipe used for sending output
	 */
	const Pipe& Out() const { return pipes[! swapped]; }

	/**
	 * @return a file descriptor that may used for receiving messages by
	 * polling/reading it.
	 */
	int InFD() const { return In().ReadFD(); }

	/**
	 * @return a file descriptor that may be used for sending messages by
	 * writing to it.
	 */
	int OutFD() const { return Out().WriteFD(); }

	/**
	 * Swaps the meaning of the pipes in the pair.  E.g. call this after
	 * fork()'ing so that the child process uses the right pipe for
	 * reading/writing.
	 */
	void Swap() { swapped = ! swapped; }

private:
	Pipe pipes[2];
	bool swapped = false;
	};

	} // namespace zeek::detail
