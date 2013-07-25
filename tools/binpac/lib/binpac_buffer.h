#ifndef binpac_buffer_h
#define binpac_buffer_h

#include <sys/types.h>
#include "binpac.h"

namespace binpac {

class FlowBuffer {
public:
	enum LineBreakStyle {
		CR_OR_LF, 	// CR or LF or CRLF
		STRICT_CRLF, 	// CR followed by LF
		CR_LF_NUL,	// CR or LF or CR-LF or CR-NUL
	};

	FlowBuffer(LineBreakStyle linebreak_style = CR_OR_LF);
	virtual ~FlowBuffer();

	void NewData(const_byteptr begin, const_byteptr end);
	void NewGap(int length);

	// Interface for delayed parsing. Sometimes BinPAC doesn't get the
	// buffering right and then one can use these to feed parts
	// individually and assemble them internally. After calling
	// FinishBuffer(), one can send the uppper-layer flow an FlowEOF() to
	// trigger parsing.
	void BufferData(const_byteptr data, const_byteptr end);
	void FinishBuffer();

	// Discard unprocessed data
	void DiscardData();

	// Whether there is enough data for the frame
	bool ready() const{ return message_complete_ || mode_ == UNKNOWN_MODE; }

	inline const_byteptr begin() const
		{
		BINPAC_ASSERT(ready());
		return ( buffer_n_ == 0 ) ? 
			orig_data_begin_ : buffer_;
		}

	inline const_byteptr end() const
		{
		BINPAC_ASSERT(ready());
		if ( buffer_n_ == 0 )
			{
			BINPAC_ASSERT(frame_length_ >= 0);
			const_byteptr end = orig_data_begin_ + frame_length_;
			BINPAC_ASSERT(end <= orig_data_end_);
			return end;
			}
		else
			return buffer_ + buffer_n_;
		}

	inline int data_length() const
		{
		if ( buffer_n_ > 0 ) 
			return buffer_n_;

		if ( frame_length_ < 0 ||
		     orig_data_begin_ + frame_length_ > orig_data_end_ )
			return orig_data_end_ - orig_data_begin_;
		else
			return frame_length_;
		}

	inline bool data_available() const
	        {
		return buffer_n_ > 0 || orig_data_end_ > orig_data_begin_;
		}

	void NewLine();
	// A negative frame_length represents a frame till EOF
	void NewFrame(int frame_length, bool chunked_);
	void GrowFrame(int new_frame_length);

	int data_seq() const
		{ 
		int data_seq_at_orig_data_begin = 
			data_seq_at_orig_data_end_ - 
			(orig_data_end_ - orig_data_begin_);
		if ( buffer_n_ > 0 )
			return data_seq_at_orig_data_begin;
		else
			return data_seq_at_orig_data_begin + data_length(); 
		}
	bool eof() const	{ return eof_; }
	void set_eof();

	bool have_pending_request() const { return have_pending_request_; }

protected:
	// Reset the buffer for a new message
	void NewMessage();

	void ClearPreviousData();

	// Expand the buffer to at least <length> bytes. If there 
	// are contents in the existing buffer, copy them to the new
	// buffer.
	void ExpandBuffer(int length);

	// Reset line state when transit from frame mode to line mode.
	void ResetLineState();

	void AppendToBuffer(const_byteptr data, int len);

	// MarkOrCopy{Line,Frame} sets message_complete_ and
	// marks begin/end pointers if a line/frame is complete, 
	// otherwise it clears message_complete_ and copies all 
	// the original data to the buffer.
	//
	void MarkOrCopy();
	void MarkOrCopyLine();
	void MarkOrCopyFrame();

	void MarkOrCopyLine_CR_OR_LF();
	void MarkOrCopyLine_STRICT_CRLF();

	int 	buffer_n_;		// number of bytes in the buffer
	int 	buffer_length_;	// size of the buffer
	u_char	*buffer_;
	bool 	message_complete_;
	int 	frame_length_;
	bool	chunked_;
	const_byteptr orig_data_begin_, orig_data_end_;

	LineBreakStyle linebreak_style_;

	enum {
		UNKNOWN_MODE,
		LINE_MODE,
		FRAME_MODE,
	} mode_;

	enum {
		CR_OR_LF_0,
		CR_OR_LF_1,
		STRICT_CRLF_0,
		STRICT_CRLF_1,
		FRAME_0,
	} state_;

	int 	data_seq_at_orig_data_end_;
	bool 	eof_;
	bool    have_pending_request_;
};

typedef FlowBuffer *flow_buffer_t;

}  // namespace binpac

#endif // binpac_buffer_h
