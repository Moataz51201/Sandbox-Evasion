# Sandbox-Evasion

it is a proof-of-concept (PoC) malware project that demonstrates advanced sandbox detection and shellcode injection techniques. It includes features like patching the Process Environment Block (PEB), checking for sandbox indicators, and dynamically executing shellcode in a target process.

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes only**. Use it ethically and with explicit permission in controlled environments. Unauthorized use may violate laws and ethical guidelines.

---

## Features

- **PEB Patching**: Patches the `PEB->BeingDebugged` flag to hide the process from debuggers.
- **Domain Controller Check**: Ensures execution only in a specific environment.
- **Memory and IP Validation**: Detects sandbox environments using memory and geolocation checks.
- **Dynamic Shellcode Execution**: Downloads and executes shellcode in a target process's memory.
- **C2 Server Integration**: Customizable Command and Control (C2) server for payload hosting.

---

## How It Works

The tool follows these steps to determine if it should execute the payload:

1. **PEB Debugging Flag Check**:
   - Uses `PatchPEBForDebugger()` to modify the `PEB->BeingDebugged` flag.

2. **Domain Controller Detection**:
   - Confirms execution in a secure environment by checking for domain controllers.

3. **Memory Check**:
   - Detects sandbox indicators by analyzing available memory.

4. **IP Geolocation**:
   - Ensures the IP address matches the expected country (e.g., "Egypt").

5. **Shellcode Execution**:
   - If all conditions are met, downloads shellcode from the C2 server and injects it into a target process.

---

## Pre-requisites

- **Operating System**: Windows 10 or higher
- **Development Environment**: Visual Studio or MinGW
- **C2 Server**: Host the shellcode at a public URL (e.g., `http://192.168.x.x/index.raw`)

---

## Build Instructions
1. Clone the repository:
   git clone https://github.com/yourusername/AntiSandboxTool.git
   cd AntiSandboxTool
Open the project in Visual Studio or compile it with MinGW.

# Usage
Start the target process (e.g., explorer.exe).
Run the compiled binary:
AntiSandboxTool.exe
