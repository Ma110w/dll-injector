# DLL Injector

An advanced DLL injection tool developed in Go, designed for the Windows platform, offering multiple injection methods and sophisticated anti-detection features. The tool provides both Fyne and giu (Dear ImGui) GUI frameworks for different user preferences.

## Screenshot

![DLL Injector UI](https://github.com/whispin/dll-injector/blob/main/screenshot/main-ui.jpg?raw=true)

## Features

### 🎯 Injection Methods
- **Standard Injection** - Classic CreateRemoteThread injection
- **SetWindowsHookEx** - Hook-based injection method
- **QueueUserAPC** - Asynchronous Procedure Call injection
- **Early Bird APC** - APC injection during process creation
- **DLL Notification** - Notification-based injection
- **CryoBird (Job Object)** - Cold injection using job objects

### 🛡️ Anti-Detection Techniques

#### Basic Bypass Options
- **Memory Load** - Load DLL directly from memory
- **PE Header Erasure** - Remove PE headers after injection
- **Entry Point Erasure** - Overwrite entry point with NOPs
- **Manual Mapping** - Manual PE mapping without LoadLibrary
- **Invisible Memory** - Allocate in high address space
- **Path Spoofing** - Disguise DLL path as system DLL

#### Advanced Bypass Options
- **Legitimate Process Injection** - Inject into trusted processes
- **PTE Spoofing** - Page Table Entry manipulation
- **VAD Manipulation** - Virtual Address Descriptor modification
- **Remove VAD Node** - Remove memory allocation records
- **Thread Stack Allocation** - Allocate behind thread stack
- **Direct Syscalls** - Bypass API hooks with direct system calls

#### Enhanced Techniques
- **Randomize Allocation** - Random memory allocation patterns
- **Delayed Execution** - Add random delays during injection
- **Multi-Stage Injection** - Split injection into multiple stages
- **Anti-Debug Techniques** - Apply anti-debugging measures
- **Process Hollowing** - Replace legitimate process memory
- **Atom Bombing** - Use atom tables for injection
- **Process Doppelganging** - Advanced process replacement
- **Ghost Writing** - Stealthy memory writing techniques
- **Module Stomping** - Overwrite legitimate modules
- **Thread Hijacking** - Hijack existing threads
- **APC Queueing** - Advanced APC manipulation
- **Memory Fluctuation** - Dynamic memory permission changes
- **Anti-VM Techniques** - Virtual machine detection evasion
- **Process Mirroring** - Mirror legitimate process behavior
- **Stealthy Threads** - Create hidden execution threads

### 🖥️ User Interface
- **Dual GUI Support** - Both Fyne and giu (Dear ImGui) frameworks
- **Modern Design** - Clean, responsive interface with VS Code-inspired theme
- **Process Management** - Real-time process list with search and filtering
- **Internationalization** - Multi-language support (English/Chinese)
- **Real-time Logging** - Live injection status and detailed logging
- **Interactive Controls** - Intuitive checkboxes and radio buttons for options

### 🌐 Internationalization
- **Auto-detection** - Automatic language detection based on OS locale
- **Chinese Support** - Full Chinese interface when OS language is Chinese
- **English Default** - English interface for all other locales

## System Requirements

- **Operating System**: Windows 10/11 (x64 or x86)
- **Go Version**: Go 1.24+ (for building from source)
- **Architecture**: AMD64 (x64) or 386 (x86)

## Quick Start

### Download Pre-built Binaries
Download the latest release from [GitHub Releases](https://github.com/whispin/dll-injector/releases):
- `dll-injector-x64.exe` - For 64-bit Windows
- `dll-injector-x86.exe` - For 32-bit Windows

### Build from Source

1. **Install Go 1.24+**
   ```bash
   # Verify Go installation
   go version
   ```

2. **Clone Repository**
   ```bash
   git clone https://github.com/whispin/dll-injector.git
   cd dll-injector
   ```

3. **Install Dependencies**
   ```bash
   go mod tidy
   ```

4. **Build Application**
   ```bash
   # Standard build
   go build ./cmd/injector

   # Optimized build (recommended)
   go build -ldflags="-s -w -H windowsgui" -o dll-injector.exe ./cmd/injector
   ```

### Build Options
- **Standard Build**: `go build ./cmd/injector`
- **Optimized Build**: `go build -ldflags="-s -w -H windowsgui" -o dll-injector.exe ./cmd/injector`
- **Cross-compile for 32-bit**: `GOARCH=386 go build -ldflags="-s -w -H windowsgui" -o dll-injector-x86.exe ./cmd/injector`

## Usage

### Basic Usage
1. **Launch Application**
   ```bash
   ./dll-injector.exe
   ```

2. **Select DLL File**
   - Click "Browse" button or enter DLL path manually
   - Supports any Windows DLL file

3. **Choose Target Process**
   - Browse the process list in the right panel
   - Use search functionality to filter processes
   - Click "Select" next to your target process

4. **Configure Injection Method**
   - Choose from 6 available injection methods
   - Standard Injection is recommended for beginners

5. **Set Anti-Detection Options**
   - Enable basic bypass options for simple evasion
   - Use advanced options for sophisticated anti-detection
   - Enhanced options provide cutting-edge techniques

6. **Execute Injection**
   - Click "INJECT DLL" button
   - Monitor real-time logs for injection status
   - Check for success/error messages

### Advanced Configuration

#### Injection Method Selection
- **Standard**: Best compatibility, easiest to detect
- **SetWindowsHookEx**: Good for UI applications
- **QueueUserAPC**: Stealthy, works with sleeping threads
- **Early Bird APC**: Effective during process startup
- **DLL Notification**: Advanced notification-based method
- **CryoBird**: Cold injection using job objects

#### Anti-Detection Strategy
1. **Basic Evasion**: Enable Memory Load + PE Header Erasure
2. **Moderate Evasion**: Add Manual Mapping + Path Spoofing
3. **Advanced Evasion**: Include VAD Manipulation + Direct Syscalls
4. **Maximum Stealth**: Enable enhanced options like Process Hollowing

## Project Structure

```
dll-injector/
├── cmd/injector/           # Main application entry point
├── internal/
│   ├── i18n/              # Internationalization support
│   ├── injector/          # Core DLL injection engine
│   │   ├── injector.go    # Main injector logic
│   │   ├── advanced_bypass.go  # Advanced anti-detection
│   │   ├── enhanced_bypass.go  # Enhanced techniques
│   │   ├── bypass.go      # Basic bypass methods
│   │   ├── pe.go          # PE file manipulation
│   │   └── memory_load.go # Memory loading functions
│   ├── process/           # Process management
│   │   ├── info.go        # Process enumeration
│   │   └── giu_icon.go    # Process icons
│   ├── ui/                # User interface
│   │   ├── application.go # Fyne-based GUI
│   │   ├── giu_application.go # giu-based GUI
│   │   ├── widgets.go     # Custom UI components
│   │   └── theme.go       # UI theming
│   └── memory/            # Memory management utilities
├── .github/workflows/     # CI/CD automation
├── screenshot/            # Application screenshots
└── README.md             # This file
```

## Development

### Prerequisites
- Go 1.24+
- Windows SDK (for CGO compilation)
- Git

### Building for Different Architectures
```bash
# AMD64 (64-bit)
GOARCH=amd64 go build -ldflags="-s -w -H windowsgui" -o dll-injector-x64.exe ./cmd/injector

# 386 (32-bit)
GOARCH=386 go build -ldflags="-s -w -H windowsgui" -o dll-injector-x86.exe ./cmd/injector
```

### Testing
```bash
# Run tests
go test ./...

# Run with race detection
go test -race ./...
```

## CI/CD

The project uses GitHub Actions for automated building and releasing:

- **Continuous Integration**: Builds and tests on every push/PR
- **Automated Releases**: Creates releases with compressed binaries
- **Multi-Architecture**: Builds both x64 and x86 versions
- **Binary Compression**: Uses UPX for smaller file sizes

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security Considerations

⚠️ **Important Security Notice**

- This tool is designed for **educational and research purposes only**
- DLL injection can be detected by modern antivirus software
- Use only on systems you own or have explicit permission to test
- Be aware of legal implications in your jurisdiction
- The authors are not responsible for misuse of this software

### Responsible Use Guidelines
- Only inject into processes you own or have permission to modify
- Test in isolated environments (VMs, sandboxes)
- Respect software licenses and terms of service
- Use for legitimate security research and education

## Troubleshooting

### Common Issues

1. **Build Errors**
   - Ensure Go 1.24+ is installed
   - Run `go mod tidy` to resolve dependencies
   - Check that CGO is enabled for GUI compilation

2. **Injection Failures**
   - Try different injection methods
   - Enable anti-detection options
   - Check target process architecture (32-bit vs 64-bit)
   - Ensure DLL is compatible with target process

3. **Access Denied**
   - Run as Administrator
   - Check Windows Defender/antivirus settings
   - Verify target process permissions

4. **GUI Issues**
   - Update graphics drivers
   - Try different UI framework (Fyne vs giu)
   - Check Windows compatibility mode

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided for educational and research purposes only. The authors and contributors are not responsible for any misuse or damage caused by this software. Users are solely responsible for ensuring their use complies with applicable laws and regulations.