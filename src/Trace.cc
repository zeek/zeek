
#include "zeek/Trace.h"

#include "zeek/Event.h"
#include "zeek/RunState.h"

#include "opentelemetry/context/context.h"
#include "opentelemetry/exporters/jaeger/jaeger_exporter.h"
#include "opentelemetry/exporters/ostream/span_exporter.h"
#include "opentelemetry/sdk/trace/batch_span_processor.h"
#include "opentelemetry/sdk/trace/simple_processor.h"
#include "opentelemetry/sdk/trace/tracer_provider.h"
#include "opentelemetry/trace/context.h"
#include "opentelemetry/trace/propagation/http_trace_context.h"
#include "opentelemetry/trace/provider.h"

namespace trace_api = opentelemetry::trace;
namespace trace_sdk = opentelemetry::sdk::trace;
namespace nostd = opentelemetry::nostd;

namespace zeek
	{

extern const char* zeek_version();

namespace trace
	{
opentelemetry::nostd::shared_ptr<opentelemetry::trace::Tracer> tracer;

opentelemetry::nostd::shared_ptr<opentelemetry::trace::Span> rootSpan;

TraceOptions options;

trace_sdk::SpanProcessor* spanProcessor;

void SetupTracing(int zeek_argc, char** zeek_argv)
	{
	options = zeek::trace::TraceOptions();
	options.trace_logging = true;
	options.trace_eventmgr = true;

	opentelemetry::exporter::jaeger::JaegerExporterOptions opts;
	opts.endpoint = "localhost";
	opts.server_port = 6831;
	auto jaeger_udp_exporter = std::unique_ptr<trace_sdk::SpanExporter>(
		new opentelemetry::exporter::jaeger::JaegerExporter(opts));
	// auto jaeger_udp_exporter = std::unique_ptr<trace_sdk::SpanExporter>(
	//		new opentelemetry::exporter::trace::OStreamSpanExporter);

	std::unique_ptr<trace_sdk::SpanProcessor> processor;
	if ( zeek::trace::options.use_batch_span_processor )
		{
		auto span_options = trace_sdk::BatchSpanProcessorOptions();
		span_options.max_export_batch_size = 32;
		processor = std::unique_ptr<trace_sdk::SpanProcessor>(
			new trace_sdk::BatchSpanProcessor(std::move(jaeger_udp_exporter), span_options));
		}
	else
		{
		processor = std::unique_ptr<trace_sdk::SpanProcessor>(
			new trace_sdk::SimpleSpanProcessor(std::move(jaeger_udp_exporter)));
		}

	// XXX is this okay? Processor is std::move'd into the tracer provider later, but we need to
	// keep it around to flush and shut it down later before we exit.
	spanProcessor = processor.get();

	auto resource_attributes = opentelemetry::sdk::resource::ResourceAttributes{
		{"service.name", "zeek"},
		//		{"zeek.script.prefixes", options.script_prefixes}
	};

	auto resource = opentelemetry::sdk::resource::Resource::Create(resource_attributes);
	auto tracer_provider = nostd::shared_ptr<trace_api::TracerProvider>(
		new trace_sdk::TracerProvider(std::move(processor), std::move(resource)));

	// Set the global trace provider
	trace_api::Provider::SetTracerProvider(tracer_provider);

	tracer = tracer_provider->GetTracer("zeek", zeek_version());

	// The EventMgr has already been created before we set the global tracer above, so it
	// can't use GetTracerIfEnabled in its constructor, etc.. Instead, we inject its tracer here.
	event_mgr.tracer = zeek::trace::GetTracerIfEnabled(zeek::trace::options.trace_eventmgr);

	// RunState's init_run isn't always called, so we ensure this is set here.
	zeek::run_state::detail::tracer = zeek::trace::GetTracerIfEnabled(
		zeek::trace::options.trace_runstate);

	// Lastly, start our root span and make it active
	rootSpan = zeek::trace::tracer->StartSpan("root span");

	// We do this dance to make it active instead of using WithActiveSpan to keep the root span open
	// until it is closed in Shutdown from atexit_handler.
	auto ctx = opentelemetry::context::RuntimeContext::GetCurrent();
	opentelemetry::context::RuntimeContext::Attach(opentelemetry::trace::SetSpan(ctx, rootSpan));

	std::vector<opentelemetry::nostd::string_view> otel_argv;
	for ( int i = 0; i < zeek_argc; i++ )
		{
		otel_argv.push_back(zeek_argv[i]);
		}
	rootSpan->SetAttribute("argv", opentelemetry::common::AttributeValue(otel_argv));
	}

/*
 * We just flush now, and wait to shutdown the span processor at final shutdown.
 */
void EarlyShutdown()
	{
	if ( spanProcessor )
		{
		spanProcessor->ForceFlush();
		}
	else
		{
		fprintf(stdout, "zeek::trace::EarlyShutdown called with no spanProcessor\n");
		}
	}

void Shutdown()
	{
	if ( rootSpan )
		{
		rootSpan->End();
		}

	if ( spanProcessor )
		{
		spanProcessor->ForceFlush();
		spanProcessor->Shutdown();
		}
	else
		{
		fprintf(stdout, "zeek::trace::Shutdown called with no spanProcessor\n");
		}
	}

opentelemetry::nostd::shared_ptr<opentelemetry::trace::Tracer> GetTracerIfEnabled(bool condition)
	{
	if ( condition )
		{
		assert(tracer);
		return tracer;
		}
	else
		{
		return std::shared_ptr<trace_api::Tracer>(new trace_api::NoopTracer());
		}
	}

opentelemetry::nostd::shared_ptr<opentelemetry::trace::Span>
StartSpanForAsync(const char* name, opentelemetry::trace::SpanContext async_context)
	{
	if ( zeek::trace::options.follow_async_messages )
		{
		opentelemetry::trace::StartSpanOptions span_options;
		span_options.parent = async_context;

		return zeek::trace::tracer->StartSpan(
			name, {{}}, {{zeek::trace::tracer->GetCurrentSpan()->GetContext(), {{}}}},
			span_options);
		}
	else
		{
		return zeek::trace::tracer->StartSpan(name, {{}}, {{async_context, {{}}}});
		}
	}

bool IsValidVersion(opentelemetry::nostd::string_view version_hex)
	{
	uint8_t version;
	opentelemetry::trace::propagation::detail::HexToBinary(version_hex, &version, sizeof(version));
	return version != 0xFF; // opentelemetry::trace::propagation::kInvalidVersion (private);
	}

// from opentelemetry/trace/propagation/http_trace_context.h
opentelemetry::trace::SpanContext
ExtractContextFromTraceHeaders(opentelemetry::nostd::string_view trace_parent,
                               opentelemetry::nostd::string_view trace_state)
	{
	if ( trace_parent.size() != opentelemetry::trace::propagation::kTraceParentSize )
		{
		return opentelemetry::trace::SpanContext::GetInvalid();
		}

	std::array<opentelemetry::nostd::string_view, 4> fields{};
	if ( opentelemetry::trace::propagation::detail::SplitString(trace_parent, '-', fields.data(),
	                                                            4) != 4 )
		{
		return opentelemetry::trace::SpanContext::GetInvalid();
		}

	opentelemetry::nostd::string_view version_hex = fields[0];
	opentelemetry::nostd::string_view trace_id_hex = fields[1];
	opentelemetry::nostd::string_view span_id_hex = fields[2];
	opentelemetry::nostd::string_view trace_flags_hex = fields[3];

	if ( version_hex.size() != opentelemetry::trace::propagation::kVersionSize ||
	     trace_id_hex.size() != opentelemetry::trace::propagation::kTraceIdSize ||
	     span_id_hex.size() != opentelemetry::trace::propagation::kSpanIdSize ||
	     trace_flags_hex.size() != opentelemetry::trace::propagation::kTraceFlagsSize )
		{
		return opentelemetry::trace::SpanContext::GetInvalid();
		}

	if ( ! opentelemetry::trace::propagation::detail::IsValidHex(version_hex) ||
	     ! opentelemetry::trace::propagation::detail::IsValidHex(trace_id_hex) ||
	     ! opentelemetry::trace::propagation::detail::IsValidHex(span_id_hex) ||
	     ! opentelemetry::trace::propagation::detail::IsValidHex(trace_flags_hex) )
		{
		return opentelemetry::trace::SpanContext::GetInvalid();
		}

	if ( ! IsValidVersion(version_hex) )
		{
		return opentelemetry::trace::SpanContext::GetInvalid();
		}

	opentelemetry::trace::TraceId trace_id =
		opentelemetry::trace::propagation::HttpTraceContext::TraceIdFromHex(trace_id_hex);
	opentelemetry::trace::SpanId span_id =
		opentelemetry::trace::propagation::HttpTraceContext::SpanIdFromHex(span_id_hex);

	if ( ! trace_id.IsValid() || ! span_id.IsValid() )
		{
		return opentelemetry::trace::SpanContext::GetInvalid();
		}

	return opentelemetry::trace::SpanContext(
		trace_id, span_id,
		opentelemetry::trace::propagation::HttpTraceContext::TraceFlagsFromHex(trace_flags_hex),
		true, opentelemetry::trace::TraceState::FromHeader(trace_state));
	}

// mostly from opentelemetry/trace/propagation/http_trace_context.h
std::string TraceParent(opentelemetry::trace::SpanContext span_context)
	{
	char trace_parent[opentelemetry::trace::propagation::kTraceParentSize + 1];
	trace_parent[0] = '0';
	trace_parent[1] = '0';
	trace_parent[2] = '-';
	span_context.trace_id().ToLowerBase16(
		opentelemetry::nostd::span<char, 2 * opentelemetry::trace::TraceId::kSize>{
			&trace_parent[3], opentelemetry::trace::propagation::kTraceIdSize});
	trace_parent[opentelemetry::trace::propagation::kTraceIdSize + 3] = '-';
	span_context.span_id().ToLowerBase16(
		opentelemetry::nostd::span<char, 2 * opentelemetry::trace::SpanId::kSize>{
			&trace_parent[opentelemetry::trace::propagation::kTraceIdSize + 4],
			opentelemetry::trace::propagation::kSpanIdSize});
	trace_parent[opentelemetry::trace::propagation::kTraceIdSize +
	             opentelemetry::trace::propagation::kSpanIdSize + 4] = '-';
	span_context.trace_flags().ToLowerBase16(opentelemetry::nostd::span<char, 2>{
		&trace_parent[opentelemetry::trace::propagation::kTraceIdSize +
	                  opentelemetry::trace::propagation::kSpanIdSize + 5],
		2});

	// XXX Is this a good way to do this? Possible memory leak or re-use of the buffer?
	trace_parent[opentelemetry::trace::propagation::kTraceParentSize] = '\0';
	return trace_parent;
	}

	} // namespace trace
	} // namespace zeek
