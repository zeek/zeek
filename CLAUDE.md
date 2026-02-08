# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Zeek is a powerful network security monitoring framework written primarily in C++ with a domain-specific scripting language. The codebase consists of a C++ core engine for packet processing and protocol analysis, a scripting language for policy implementation, and an extensive set of protocol analyzers.

## Building and Testing

### Initial Setup

```bash
# Clone with submodules (required)
git clone --recursive https://github.com/zeek/zeek

# Configure the build (creates build/ directory)
./configure [OPTIONS]

# Common configure options:
#   --prefix=PATH                # Installation directory (default: /usr/local/zeek)
#   --build-type=TYPE            # Debug, Release, RelWithDebInfo (default)
#   --enable-debug               # Compile with debugging support
#   --enable-ccache              # Use ccache for faster rebuilds
#   --disable-spicy              # Disable Spicy parser generator
#   --sanitizers=asan,ubsan      # Enable sanitizers
```

### Building

```bash
# Build everything
make

# Install to prefix directory
make install

# Clean build artifacts
make clean

# Remove build directory entirely
make distclean
```

### Running Tests

```bash
# Run the main BTest suite
make test

# Run auxiliary tests (zeekctl, plugins, etc.)
make test-aux

# Run all tests
make test-all

# Run specific test categories
cd testing/btest
btest scripts             # Test script functionality
btest core                # Test core C++ functionality
btest language            # Test language features

# Run a specific test
btest scripts/base/protocols/http/main.zeek
```

The testing framework (BTest) compares actual output against baselines in `testing/btest/Baseline/`. Test inputs include Zeek scripts and packet captures (`testing/btest/Traces/`).

### Single Test Development

When debugging or developing a specific test:

```bash
cd testing/btest
btest -d <test-path>      # Run with diagnostics
btest -u <test-path>      # Update baseline if output is correct
btest -v <test-path>      # Verbose output
```

## Architecture Overview

### Core Components

**Packet Processing Pipeline:**
1. **Packet Capture** (`src/iosource/`) - libpcap-based packet acquisition
2. **Packet Analysis** (`src/packet_analysis/`) - Low-level packet parsing (Ethernet, IP, TCP, UDP, etc.)
3. **Connection Tracking** (`src/session/`) - TCP stream reassembly and connection state
4. **Protocol Analysis** (`src/analyzer/`) - Application-layer protocol dissection (HTTP, DNS, SSL, etc.)
5. **File Analysis** (`src/file_analysis/`) - File extraction and analysis from network streams

**Script Execution:**
- **Interpreter** (`src/Expr.cc`, `src/Stmt.cc`, `src/Val.cc`) - Core script evaluation engine
- **ZAM Optimizer** (`src/script_opt/ZAM/`) - Bytecode compilation with `-O ZAM`
- **C++ Compiler** (`src/script_opt/CPP/`) - Native compilation with `-O gen-C++` and `-O use-C++`
- **BIF System** (`.bif` files) - Built-in functions that expose C++ to scripts

**Communication & Distribution:**
- **Broker** (`src/broker/`, `auxil/broker/`) - Inter-process messaging and distributed data stores
- **Cluster** (`src/cluster/`) - Load balancing and cluster management

### Directory Structure

| Path | Purpose |
|------|---------|
| `src/` | C++ implementation of core engine |
| `src/analyzer/protocol/` | 50+ protocol analyzers (DNS, HTTP, SSH, SSL, SMB, etc.) |
| `src/packet_analysis/protocol/` | Low-level packet parsers (IP, TCP, UDP, VLAN, etc.) |
| `src/script_opt/ZAM/` | Zeek Abstract Machine bytecode compiler |
| `src/script_opt/CPP/` | C++ script compiler for maximum performance |
| `src/broker/` | Broker communication bindings |
| `scripts/base/` | Default policy scripts (loaded unless `-b` flag used) |
| `scripts/base/frameworks/` | Core frameworks (logging, notice, intel, files, etc.) |
| `scripts/base/protocols/` | Protocol-specific scripts matching C++ analyzers |
| `scripts/policy/` | Optional policy scripts |
| `testing/btest/` | BTest test suite |
| `testing/btest/Traces/` | PCAP files for testing |
| `testing/btest/Baseline/` | Expected test outputs |
| `auxil/broker/` | Broker communication library (submodule) |
| `auxil/spicy/` | Spicy protocol parser generator (submodule) |
| `auxil/zeekctl/` | ZeekControl deployment tool (submodule) |
| `tools/` | Development tools (bifcl, gen-zam, etc.) |

### Key Source Files

- `src/main.cc` - Entry point
- `src/Expr.cc/h` - Expression AST and evaluation
- `src/Stmt.cc/h` - Statement types and execution
- `src/Type.cc/h` - Type system (tables, records, functions, etc.)
- `src/Val.cc/h` - Value representation and manipulation
- `src/Event.cc/h` - Event system
- `src/analyzer/Analyzer.cc/h` - Base analyzer class
- `src/analyzer/Manager.cc` - Analyzer instantiation and management
- `src/packet_analysis/Manager.cc` - Packet dispatcher

## Script and C++ Integration

### How Scripts Call C++ (BIFs)

Built-In Functions are defined in `.bif` files throughout the codebase:

```
src/zeek.bif                               # Core functions (print, fmt, etc.)
src/analyzer/protocol/dns/events.bif       # DNS-specific functions
src/broker/messaging.bif                   # Broker messaging functions
```

The `bifcl` tool (BIF compiler) processes these files during build to generate:
- C++ function implementations (`.bif.cc`)
- Zeek script declarations (`.zeek` files in `scripts/base/bif/`)

**Example BIF definition:**
```cpp
%%{
// C++ includes and helper code
%%}

## Zeek script documentation
function my_function(arg: string): bool
    %{
    // C++ implementation
    return val_mgr->True();
    %}
```

### How C++ Calls Scripts (Events)

Protocol analyzers generate events that are handled by Zeek scripts:

1. C++ code fires events: `event_mgr.Enqueue(event_name, args...)`
2. Event handlers in scripts are invoked: `event http_request(...)`
3. Common events: `zeek_init`, `zeek_done`, `connection_established`, protocol-specific events

### Script Loading Process

1. `scripts/base/init-bare.zeek` - Minimal core types
2. `scripts/base/init-default.zeek` - Loads all default frameworks and protocols
3. Protocol scripts in `scripts/base/protocols/` mirror analyzers in `src/analyzer/protocol/`
4. Site-specific scripts in `scripts/site/` for local customization

## Protocol Analyzers

Each protocol analyzer typically includes:

**C++ Components:**
- `src/analyzer/protocol/<proto>/<Proto>.cc/h` - Main analyzer implementation
- `src/analyzer/protocol/<proto>/events.bif` - Event and function definitions
- `src/analyzer/protocol/<proto>/<proto>-analyzer.pac` - BinPAC parser (if used)

**Script Components:**
- `scripts/base/protocols/<proto>/main.zeek` - Primary script logic
- `scripts/base/protocols/<proto>/utils.zeek` - Utility functions
- `scripts/base/bif/<proto>.zeek` - Generated BIF declarations

**Adding a new analyzer requires:**
1. Implementing the analyzer class inheriting from `analyzer::Analyzer`
2. Defining events in a `.bif` file
3. Registering the analyzer with the analyzer manager
4. Writing corresponding Zeek scripts to handle events
5. Adding tests in `testing/btest/scripts/base/protocols/<proto>/`

## Code Generation

The build system generates code from various domain-specific files:

| Source | Tool | Output |
|--------|------|--------|
| `*.bif` | bifcl | C++ implementations + Zeek declarations |
| `*.pac` | binpac | Protocol parser C++ code |
| `parse.y`, `rule-parse.y` | bison | Parser C++ code |
| `scan.l`, `rule-scan.l` | flex | Lexer C++ code |
| `script_opt/ZAM/OPs/*.op` | gen-zam | ZAM bytecode operations |

These generated files are placed in the `build/` directory and should not be manually edited.

## Development Workflow

### Modifying C++ Code

1. Edit source files in `src/`
2. Run `make` from the repository root
3. Test with `make test` or run `build/src/zeek` directly
4. For specific tests: `cd testing/btest && btest <test-path>`

### Modifying Zeek Scripts

Scripts in `scripts/` are copied to the installation directory. During development:

```bash
# Test a script directly
./build/src/zeek path/to/script.zeek

# Test with a packet capture
./build/src/zeek -r testing/btest/Traces/http.pcap scripts/base/protocols/http/main.zeek

# Use development script paths
eval $(./build/zeek-path-dev)
zeek -r pcap-file script.zeek
```

### Adding New BIFs

1. Add function definition to appropriate `.bif` file or create new one
2. Add `.bif` file to `src/CMakeLists.txt` if new
3. Run `make` - bifcl will generate necessary files
4. Zeek scripts can now call the function

### Debugging

```bash
# Build with debug symbols
./configure --enable-debug
make

# Run under debugger
gdb --args ./build/src/zeek script.zeek

# Enable debug output
./build/src/zeek -B dpd script.zeek    # Debug dynamic protocol detection
./build/src/zeek -B debug script.zeek  # General debug output
```

## Script Optimization

Zeek supports two optimization modes for improved script performance:

### ZAM (Zeek Abstract Machine)

Bytecode compilation for faster script execution:

```bash
./build/src/zeek -O ZAM script.zeek
```

Implementation in `src/script_opt/ZAM/`. Operations defined in `src/script_opt/ZAM/OPs/`.

### C++ Compilation

Compile scripts to native C++ for maximum performance:

```bash
# Generate C++ code
./build/src/zeek -O gen-C++ script.zeek

# Use compiled code
./build/src/zeek -O use-C++ script.zeek
```

Implementation in `src/script_opt/CPP/`. Generated code appears in `build/CPP-gen.cc`.

## Common Pitfalls

- **Forgetting `--recursive`**: Zeek requires submodules. Always clone with `--recursive` or run `git submodule update --init --recursive`
- **Not rebuilding after BIF changes**: Changes to `.bif` files require running `make` to regenerate code
- **Using absolute paths in tests**: BTest tests should use relative paths and environment variables like `$TRACES`
- **Modifying generated files**: Never edit files in `build/` - modify source templates instead
- **Missing dependencies**: Ensure libpcap, OpenSSL, Python 3.9+, and other dependencies are installed

## Performance Considerations

- **Script optimization**: Use `-O ZAM` or `-O gen-C++` for production deployments
- **Memory allocation**: Consider `--enable-jemalloc` for better memory performance
- **Packet capture**: AF_PACKET (Linux) provides better performance than libpcap for high-speed networks
- **Clustering**: Distribute load across workers using Broker and cluster framework
- **Profiling**: Use `--enable-perftools` for Google perftools integration

## Code Style

The codebase uses:
- `.clang-format` for C++ formatting
- `.clang-tidy` for C++ linting
- `ruff.toml` for Python formatting
- Pre-commit hooks (`.pre-commit-config.yaml`) for automated checks

Run formatters before committing:

```bash
# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Format all files
pre-commit run --all-files
```
