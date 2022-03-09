// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "opentelemetry/sdk/trace/tracer_provider.h"
#include "opentelemetry/trace/provider.h"

namespace zeek::trace
	{
struct TraceOptions
	{
	bool use_batch_span_processor = false;

	bool follow_async_messages = true;

	bool trace_pktsrc = true;
	bool trace_runstate = true;
	bool trace_eventmgr = true;
	bool trace_logging = true;
	};

extern TraceOptions options;

extern opentelemetry::nostd::shared_ptr<opentelemetry::trace::Tracer> tracer;

extern opentelemetry::sdk::trace::SpanProcessor* spanProcessor;

extern opentelemetry::nostd::shared_ptr<opentelemetry::trace::Span> rootSpan;

opentelemetry::nostd::shared_ptr<opentelemetry::trace::Tracer> GetTracerIfEnabled(bool condition);

opentelemetry::nostd::shared_ptr<opentelemetry::trace::Span>
StartSpanForAsync(const char* name, opentelemetry::trace::SpanContext async_context);

opentelemetry::trace::SpanContext
ExtractContextFromTraceHeaders(opentelemetry::nostd::string_view trace_parent,
                               opentelemetry::nostd::string_view trace_state);

std::string TraceParent(opentelemetry::trace::SpanContext span_context);

void SetupTracing(int zeek_argc, char** zeek_argv);

void EarlyShutdown();

void Shutdown();

	} // namespace zeek::trace
