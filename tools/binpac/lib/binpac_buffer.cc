#include <stdio.h>
#include <stdlib.h>
#include <string.h> // for memcpy

#define binpac_regex_h

#include "binpac.h"
#include "binpac_buffer.h"

namespace binpac {

extern double network_time();

namespace {
const unsigned char CR = '\r';
const unsigned char LF = '\n';
} // namespace

binpac::FlowBuffer::Policy binpac::FlowBuffer::policy = {
    // max_capacity
    10 * 1024 * 1024,
    // min_capacity
    512,
    // contract_threshold
    2 * 1024 * 1024,
};

FlowBuffer::FlowBuffer(LineBreakStyle linebreak_style) {
    buffer_length_ = 0;
    buffer_ = nullptr;

    orig_data_begin_ = nullptr;
    orig_data_end_ = nullptr;

    linebreak_style_ = linebreak_style;
    linebreak_style_default = linebreak_style;
    linebreaker_ = 0;
    ResetLineState();

    mode_ = UNKNOWN_MODE;
    frame_length_ = 0;
    chunked_ = false;

    data_seq_at_orig_data_end_ = 0;
    eof_ = false;
    have_pending_request_ = false;

    buffer_n_ = 0;

    NewMessage();
}

FlowBuffer::~FlowBuffer() {
    if ( buffer_ )
        free(buffer_);
}

void FlowBuffer::NewMessage() {
    BINPAC_ASSERT(frame_length_ >= 0);

    int bytes_to_advance = 0;
    if ( buffer_n_ == 0 ) {
        switch ( mode_ ) {
            case LINE_MODE: bytes_to_advance = (frame_length_ + (linebreak_style_ == STRICT_CRLF ? 2 : 1)); break;
            case FRAME_MODE: bytes_to_advance = frame_length_; break;
            case UNKNOWN_MODE: break;
        }
    }

    orig_data_begin_ += bytes_to_advance;
    BINPAC_ASSERT(orig_data_begin_ <= orig_data_end_);

    buffer_n_ = 0;
    message_complete_ = false;
    ContractBuffer();
}

void FlowBuffer::ResetLineState() {
    switch ( linebreak_style_ ) {
        case CR_OR_LF: state_ = CR_OR_LF_0; break;
        case STRICT_CRLF: state_ = STRICT_CRLF_0; break;
        case LINE_BREAKER: break; // Nothing to reset
        default: BINPAC_ASSERT(0); break;
    }
}

void FlowBuffer::ExpandBuffer(int length) {
    if ( buffer_length_ >= length )
        return;

    if ( length < policy.min_capacity )
        length = policy.min_capacity;

    if ( length < buffer_length_ * 2 )
        length = buffer_length_ * 2;

    if ( length > policy.max_capacity ) {
        std::string reason = strfmt("expand past max capacity %d/%d", length, policy.max_capacity);
        throw ExceptionFlowBufferAlloc(reason.c_str());
    }

    // Allocate a new buffer and copy the existing contents
    buffer_length_ = length;
    unsigned char* new_buf = (unsigned char*)realloc(buffer_, buffer_length_);

    if ( ! new_buf )
        throw ExceptionFlowBufferAlloc("expand realloc OOM");

    buffer_ = new_buf;
}

void FlowBuffer::ContractBuffer() {
    if ( buffer_length_ < policy.contract_threshold )
        return;

    buffer_length_ = policy.min_capacity;
    unsigned char* new_buf = (unsigned char*)realloc(buffer_, buffer_length_);

    if ( ! new_buf )
        throw ExceptionFlowBufferAlloc("contract realloc OOM");

    buffer_ = new_buf;
}

void FlowBuffer::SetLineBreaker(unsigned char* lbreaker) {
    linebreaker_ = *lbreaker;
    linebreak_style_default = linebreak_style_;
    linebreak_style_ = LINE_BREAKER;
}

void FlowBuffer::UnsetLineBreaker() { linebreak_style_ = linebreak_style_default; }

void FlowBuffer::NewLine() {
    FlowBuffer::NewMessage();
    mode_ = LINE_MODE;
    frame_length_ = 0;
    chunked_ = false;
    have_pending_request_ = true;
    if ( state_ == FRAME_0 )
        ResetLineState();
    MarkOrCopyLine();
}

void FlowBuffer::NewFrame(int frame_length, bool chunked) {
    FlowBuffer::NewMessage();
    mode_ = FRAME_MODE;
    frame_length_ = frame_length;
    chunked_ = chunked;
    have_pending_request_ = true;
    MarkOrCopyFrame();
}

void FlowBuffer::BufferData(const_byteptr data, const_byteptr end) {
    mode_ = FRAME_MODE;
    frame_length_ += (end - data);
    MarkOrCopyFrame();
    NewData(data, end);
}

void FlowBuffer::FinishBuffer() { message_complete_ = true; }

void FlowBuffer::GrowFrame(int length) {
    BINPAC_ASSERT(frame_length_ >= 0);
    if ( length <= frame_length_ )
        return;
    BINPAC_ASSERT(! chunked_ || frame_length_ == 0);
    mode_ = FRAME_MODE;
    frame_length_ = length;
    MarkOrCopyFrame();
}

void FlowBuffer::DiscardData() {
    mode_ = UNKNOWN_MODE;
    message_complete_ = false;
    have_pending_request_ = false;
    orig_data_begin_ = orig_data_end_ = nullptr;

    buffer_n_ = 0;
    frame_length_ = 0;
    ContractBuffer();
}

void FlowBuffer::set_eof() {
    // fprintf(stderr, "EOF\n");
    eof_ = true;
    if ( chunked_ )
        frame_length_ = orig_data_end_ - orig_data_begin_;
    if ( frame_length_ < 0 )
        frame_length_ = 0;
}

void FlowBuffer::NewData(const_byteptr begin, const_byteptr end) {
    BINPAC_ASSERT(begin <= end);

    ClearPreviousData();

    BINPAC_ASSERT((buffer_n_ == 0 && message_complete_) || orig_data_begin_ == orig_data_end_);

    orig_data_begin_ = begin;
    orig_data_end_ = end;
    data_seq_at_orig_data_end_ += (end - begin);

    MarkOrCopy();
}

void FlowBuffer::MarkOrCopy() {
    if ( ! message_complete_ ) {
        switch ( mode_ ) {
            case LINE_MODE: MarkOrCopyLine(); break;

            case FRAME_MODE: MarkOrCopyFrame(); break;

            default: break;
        }
    }
}

void FlowBuffer::ClearPreviousData() {
    // All previous data must have been processed or buffered already
    if ( orig_data_begin_ < orig_data_end_ ) {
        BINPAC_ASSERT(buffer_n_ == 0);
        if ( chunked_ ) {
            if ( frame_length_ > 0 ) {
                frame_length_ -= (orig_data_end_ - orig_data_begin_);
            }
            orig_data_begin_ = orig_data_end_;
        }
    }
}

void FlowBuffer::NewGap(int length) {
    ClearPreviousData();

    if ( chunked_ && frame_length_ >= 0 ) {
        frame_length_ -= length;
        if ( frame_length_ < 0 )
            frame_length_ = 0;
    }

    orig_data_begin_ = orig_data_end_ = nullptr;
    MarkOrCopy();
}

void FlowBuffer::MarkOrCopyLine() {
    switch ( linebreak_style_ ) {
        case CR_OR_LF: MarkOrCopyLine_CR_OR_LF(); break;
        case STRICT_CRLF: MarkOrCopyLine_STRICT_CRLF(); break;
        case LINE_BREAKER: MarkOrCopyLine_LINEBREAK(); break;
        default: BINPAC_ASSERT(0); break;
    }
}

/*
Finite state automaton for CR_OR_LF:
(!--line is complete, *--add to buffer)

CR_OR_LF_0:
    CR:	CR_OR_LF_1 !
    LF:	CR_OR_LF_0 !
    .:	CR_OR_LF_0 *

CR_OR_LF_1:
    CR:	CR_OR_LF_1 !
    LF:	CR_OR_LF_0
    .:	CR_OR_LF_0 *
*/

void FlowBuffer::MarkOrCopyLine_CR_OR_LF() {
    if ( ! (orig_data_begin_ && orig_data_end_) )
        return;

    if ( state_ == CR_OR_LF_1 && orig_data_begin_ < orig_data_end_ && *orig_data_begin_ == LF ) {
        state_ = CR_OR_LF_0;
        ++orig_data_begin_;
    }

    const_byteptr data;
    for ( data = orig_data_begin_; data < orig_data_end_; ++data ) {
        switch ( *data ) {
            case CR: state_ = CR_OR_LF_1; goto found_end_of_line;

            case LF:
                // state_ = CR_OR_LF_0;
                goto found_end_of_line;

            default:
                // state_ = CR_OR_LF_0;
                break;
        }
    }

    AppendToBuffer(orig_data_begin_, orig_data_end_ - orig_data_begin_);
    return;

found_end_of_line:
    if ( buffer_n_ == 0 ) {
        frame_length_ = data - orig_data_begin_;
    }
    else {
        AppendToBuffer(orig_data_begin_, data + 1 - orig_data_begin_);
        // But eliminate the last CR or LF
        --buffer_n_;
    }
    message_complete_ = true;

#if DEBUG_FLOW_BUFFER
    fprintf(stderr, "%.6f Line complete: [%s]\n", network_time(),
            string((const char*)begin(), (const char*)end()).c_str());
#endif
}

/*
Finite state automaton and STRICT_CRLF:
(!--line is complete, *--add to buffer)

STRICT_CRLF_0:
    CR:	STRICT_CRLF_1 *
    LF:	STRICT_CRLF_0 *
    .:	STRICT_CRLF_0 *

STRICT_CRLF_1:
    CR:	STRICT_CRLF_1 *
    LF:	STRICT_CRLF_0 ! (--buffer_n_)
    .:	STRICT_CRLF_0 *
*/

void FlowBuffer::MarkOrCopyLine_STRICT_CRLF() {
    const_byteptr data;
    for ( data = orig_data_begin_; data < orig_data_end_; ++data ) {
        switch ( *data ) {
            case CR: state_ = STRICT_CRLF_1; break;

            case LF:
                if ( state_ == STRICT_CRLF_1 ) {
                    state_ = STRICT_CRLF_0;
                    goto found_end_of_line;
                }
                break;

            default: state_ = STRICT_CRLF_0; break;
        }
    }

    AppendToBuffer(orig_data_begin_, orig_data_end_ - orig_data_begin_);
    return;

found_end_of_line:
    if ( buffer_n_ == 0 ) {
        frame_length_ = data - 1 - orig_data_begin_;
    }
    else {
        AppendToBuffer(orig_data_begin_, data + 1 - orig_data_begin_);
        // Pop the preceding CR and LF from the buffer
        buffer_n_ -= 2;
    }

    message_complete_ = true;

#if DEBUG_FLOW_BUFFER
    fprintf(stderr, "%.6f Line complete: [%s]\n", network_time(),
            string((const char*)begin(), (const char*)end()).c_str());
#endif
}

void FlowBuffer::MarkOrCopyLine_LINEBREAK() {
    if ( ! (orig_data_begin_ && orig_data_end_) )
        return;

    const_byteptr data;
    for ( data = orig_data_begin_; data < orig_data_end_; ++data ) {
        if ( *data == linebreaker_ )
            goto found_end_of_line;
    }

    AppendToBuffer(orig_data_begin_, orig_data_end_ - orig_data_begin_);
    return;

found_end_of_line:
    if ( buffer_n_ == 0 ) {
        frame_length_ = data - orig_data_begin_;
    }
    else {
        AppendToBuffer(orig_data_begin_, data + 1 - orig_data_begin_);
        // But eliminate the last 'linebreaker' character
        --buffer_n_;
    }
    message_complete_ = true;

#if DEBUG_FLOW_BUFFER
    fprintf(stderr, "%.6f Line complete: [%s]\n", network_time(),
            string((const char*)begin(), (const char*)end()).c_str());
#endif
}

// Invariants:
//
// When buffer_n_ == 0:
// Frame = [orig_data_begin_..(orig_data_begin_ + frame_length_)]
//
// When buffer_n_ > 0:
// Frame = [0..buffer_n_][orig_data_begin_..]

void FlowBuffer::MarkOrCopyFrame() {
    if ( mode_ == FRAME_MODE && state_ == CR_OR_LF_1 && orig_data_begin_ < orig_data_end_ ) {
        // Skip the lingering LF
        if ( *orig_data_begin_ == LF ) {
            ++orig_data_begin_;
        }
        state_ = FRAME_0;
    }

    if ( buffer_n_ == 0 ) {
        // If there is enough data
        if ( frame_length_ >= 0 && orig_data_end_ - orig_data_begin_ >= frame_length_ ) {
            // Do nothing except setting the message complete flag
            message_complete_ = true;
        }
        else {
            if ( ! chunked_ ) {
                AppendToBuffer(orig_data_begin_, orig_data_end_ - orig_data_begin_);
            }
            message_complete_ = false;
        }
    }
    else {
        BINPAC_ASSERT(! chunked_);
        int bytes_to_copy = orig_data_end_ - orig_data_begin_;
        message_complete_ = false;
        if ( frame_length_ >= 0 && buffer_n_ + bytes_to_copy >= frame_length_ ) {
            bytes_to_copy = frame_length_ - buffer_n_;
            message_complete_ = true;
        }
        AppendToBuffer(orig_data_begin_, bytes_to_copy);
    }

#if DEBUG_FLOW_BUFFER
    if ( message_complete_ ) {
        fprintf(stderr, "%.6f frame complete: [%s]\n", network_time(),
                string((const char*)begin(), (const char*)end()).c_str());
    }
#endif
}

void FlowBuffer::AppendToBuffer(const_byteptr data, int len) {
    if ( len <= 0 )
        return;

    BINPAC_ASSERT(! chunked_);
    ExpandBuffer(buffer_n_ + len);
    memcpy(buffer_ + buffer_n_, data, len);
    buffer_n_ += len;

    orig_data_begin_ += len;
    BINPAC_ASSERT(orig_data_begin_ <= orig_data_end_);
}

} // namespace binpac
