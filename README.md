# lu77U-MobileSec

**🛡️ Professional Mobile Security Analysis & Vulnerability Patching Tool 🔐**

An advanced, AI-powered security analysis platform for Android applications with automatic vulnerability detection and intelligent fix generation. Supports Java/Kotlin, React Native, and Flutter frameworks with comprehensive static and dynamic analysis capabilities.

## ⭐ Key Features

- **🔍 Multi-Framework Support**: Java/Kotlin, React Native, Flutter with specialized analyzers
- **🤖 AI-Powered Analysis**: Groq API and Ollama integration for intelligent vulnerability detection
- **🚀 Dynamic Analysis**: MobSF integration for real-time application testing
- **📊 Comprehensive Reporting**: Structured output with severity scoring and fix recommendations
- **🛠️ Automated Setup**: Built-in dependency installer and system doctor
- **💻 Interactive CLI**: User-friendly interface with guided analysis workflows

<details>
<summary>🔧 Installation & Setup</summary>

## Installation

### Automated Installation (Recommended)

The tool includes an automated dependency installer that handles all required tools:

```bash
# Install the package
pip install lu77U-MobileSec

# Run system doctor to install missing dependencies
lu77u-mobilesec doctor

# Start analyzing APKs
lu77u-mobilesec your-app.apk
```

### Manual Setup by Platform

**macOS**
```bash
# Using Homebrew
brew install jadx node openjdk apktool

# Install Python package
pip install lu77U-MobileSec
```

**Linux (Ubuntu/Debian)**
```bash
# Install system dependencies
sudo apt update
sudo apt install openjdk-11-jdk nodejs npm

# Download and install JADX
wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.4.7.zip
unzip jadx-1.4.7.zip -d /opt/jadx
sudo ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

# Install Python package
pip install lu77U-MobileSec
```

**Windows**
```powershell
# Using Chocolatey
choco install openjdk nodejs

# Download JADX and APKTool from GitHub releases
# Add to PATH manually

# Install Python package
pip install lu77U-MobileSec
```

### Core Dependencies

- **Python 3.8+**: Main runtime environment
- **JADX**: Java/Kotlin decompiler for Android apps  
- **Java 11+**: Required for Android build tools
- **Node.js**: Required for React Native enhanced analysis
- **APKTool**: APK resource extraction and analysis

### Optional Dependencies

- **MobSF**: Dynamic analysis platform
- **Ollama**: Local LLM runtime for AI analysis
- **Android SDK Tools**: aapt for manifest parsing
- **Blutter**: Flutter Dart code recovery tool

### AI Configuration

**Groq API (Cloud)**
```bash
# Get API key from https://console.groq.com/
export GROQ_API_KEY="your-api-key-here"
```

**Ollama (Local)**
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull DeepSeek Coder model (automatically done by tool)
ollama pull deepseek-coder:6.7b
```

</details>

<details>
<summary>📖 Usage Guide</summary>

## Usage

### Basic Command Line Usage

```bash
# Basic analysis (auto-detect framework)
lu77u-mobilesec app.apk

# Force specific framework type
lu77u-mobilesec app.apk --type react-native

# Enable AI-powered vulnerability fixing
lu77u-mobilesec app.apk --fix

# Enable dynamic analysis (requires MobSF)
lu77u-mobilesec app.apk --dynamic

# Enhanced React Native analysis
lu77u-mobilesec app.apk --type react-native --enhanced-rn

# Check system dependencies
lu77u-mobilesec doctor

# Show help
lu77u-mobilesec --help
```

### Interactive Mode

Launch guided analysis with configuration options:

```bash
# Start interactive mode
lu77u-mobilesec
```

Interactive mode provides:
- **Framework Selection**: Choose analysis type manually
- **AI Configuration**: Select between Groq and Ollama
- **Dynamic Analysis Setup**: Configure MobSF integration  
- **Debug Mode**: Enable verbose logging
- **Sample APK Access**: Built-in test applications

### Complete CLI Reference

**Arguments:**
- `APK_FILE`: Path to Android APK file to analyze
- `doctor`: Run system dependency checker and installer

**Options:**
- `--type {java,kotlin,react-native,flutter}`: Force specific analysis type
- `--fix`: Enable vulnerability auto-fix prompt after analysis
- `--dynamic`: Enable dynamic analysis using MobSF API
- `--enhanced-rn`: Use enhanced React Native analysis with decompilation
- `--llm {groq,ollama}`: Choose AI model provider (default: ollama)
- `--debug, -d`: Enable debug mode with verbose output
- `--version, -v`: Show program version and exit
- `--help, -h`: Show help message and exit

**Advanced Examples:**
```bash
# Full analysis with all features
lu77u-mobilesec app.apk --fix --dynamic --debug

# React Native with enhanced decompilation
lu77u-mobilesec app.apk --type react-native --enhanced-rn --fix

# Use Groq AI for analysis
lu77u-mobilesec app.apk --llm groq --fix

# Flutter analysis with debug output
lu77u-mobilesec app.apk --type flutter --debug --fix
```

</details>

<details>
<summary>🔍 Analysis Capabilities</summary>

## Framework-Specific Analysis

### Java/Kotlin Analysis

**Decompilation & Extraction:**
- **JADX Integration**: Full source code reconstruction from APK
- **Manifest Analysis**: Permission and component inspection
- **Resource Extraction**: Assets, strings, configuration files
- **DEX Analysis**: Dalvik bytecode processing

**Security Scanning:**
- **Code Pattern Detection**: Custom vulnerability rules
- **API Usage Analysis**: Android framework and library calls
- **Component Security**: Activity, Service, BroadcastReceiver analysis
- **Permission Analysis**: Dangerous permission usage patterns

**AI Integration:**
- **Context-Aware Analysis**: Understanding of Android architecture
- **Vulnerability Categorization**: Automatic classification and severity scoring
- **Fix Generation**: AI-generated patches for detected issues

### React Native Analysis

**Standard Analysis:**
- **Bundle Extraction**: JavaScript bundle identification and extraction
- **Bridge Analysis**: Native module interaction patterns
- **Component Scanning**: React component security assessment
- **Storage Analysis**: AsyncStorage and secure storage patterns

**Enhanced Analysis (--enhanced-rn):**
- **Bundle Decompilation**: Converts minified bundles back to readable modules
- **Module-Level Analysis**: Individual React Native module examination
- **Advanced Pattern Detection**: Bridge vulnerabilities, injection flaws
- **react-native-decompiler Integration**: Automatic tool installation and usage

**Supported Bundle Types:**
- `index.android.bundle`
- `main.jsbundle`
- Custom bundle configurations
- Hermes bytecode bundles

### Flutter Analysis

**Blutter Integration:**
- **Dart Code Recovery**: Extract Dart source from Flutter APK
- **Snapshot Analysis**: Dart VM snapshot processing
- **Asset Extraction**: Flutter-specific resource analysis

**Security Patterns:**
- **Widget Security**: Flutter widget vulnerability patterns
- **Platform Channel Analysis**: Native bridge security assessment
- **Engine Integration**: Flutter engine security evaluation

</details>

<details>
<summary>🚀 Dynamic Analysis (MobSF Integration)</summary>

## MobSF Dynamic Analysis

### Setup Requirements

1. **Install MobSF Server:**
```bash
# Clone and setup MobSF
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
./setup.sh
```

2. **Start MobSF Server:**
```bash
# Start server (usually http://localhost:8000)
python manage.py runserver
```

3. **Get API Key:**
- Access MobSF web interface
- Navigate to API Key section
- Generate and copy API key

### Dynamic Analysis Workflow

```bash
# Run with dynamic analysis
lu77u-mobilesec app.apk --dynamic
```

**Analysis Process:**
1. **APK Upload**: Automatic upload to MobSF server
2. **Static Analysis**: MobSF performs initial static scan
3. **Dynamic Setup**: Configures testing environment
4. **Runtime Testing**: Monitors application behavior
5. **Report Generation**: Combines static and dynamic results

### Dynamic Analysis Features

**Real-time Monitoring:**
- **Network Traffic**: HTTP/HTTPS request monitoring
- **File System Access**: Runtime file operation tracking
- **Component Interaction**: Activity and service behavior
- **API Endpoint Discovery**: Automatic endpoint detection

**Security Testing:**
- **SSL/TLS Validation**: Certificate and encryption analysis
- **Authentication Testing**: Session management evaluation
- **Input Validation**: Runtime injection testing
- **Permission Usage**: Runtime permission analysis

**Integration Benefits:**
- **Combined Results**: Static + dynamic vulnerability correlation
- **Behavioral Context**: Understanding of application runtime behavior
- **Network Security**: Comprehensive communication analysis
- **False Positive Reduction**: Dynamic validation of static findings

</details>

<details>
<summary>🤖 AI-Powered Analysis</summary>

## AI Integration & Capabilities

### Groq API Integration

**Features:**
- **Cloud-based Processing**: High-performance LLM analysis
- **Real-time Analysis**: Fast vulnerability detection and fix generation
- **Latest Models**: Access to cutting-edge language models
- **Scalable**: Handles large codebases efficiently

**Setup:**
```bash
# Set API key
export GROQ_API_KEY="your-groq-api-key"

# Use Groq for analysis
lu77u-mobilesec app.apk --llm groq --fix
```

### Ollama Integration (Local LLM)

**Features:**
- **Privacy-focused**: All analysis runs locally
- **DeepSeek Coder Model**: Specialized for code analysis
- **Offline Operation**: No internet required after setup
- **Cost-effective**: No API usage fees

**Setup:**
```bash
# Ollama installation (automatic via tool)
# Model download (automatic on first use)

# Use Ollama (default)
lu77u-mobilesec app.apk --fix
```

### AI Analysis Capabilities

**Vulnerability Detection:**
- **Pattern Recognition**: Advanced code pattern analysis
- **Context Understanding**: Business logic comprehension
- **Semantic Analysis**: Meaning-based vulnerability detection
- **False Positive Filtering**: Intelligent result filtering

**Fix Generation:**
- **Automated Patching**: AI-generated code fixes
- **Context-aware Solutions**: Fixes that understand application architecture
- **Multiple Fix Options**: Alternative solutions for complex issues
- **Explanation Generation**: Detailed fix rationale and implementation

**Severity Assessment:**
- **CVSS Integration**: Standard vulnerability scoring
- **Context-based Scoring**: Application-specific risk assessment
- **Business Impact Analysis**: Understanding of security implications
- **Prioritization Guidance**: Risk-based fix ordering

</details>

<details>
<summary>📊 Output Structure & Reporting</summary>

## Analysis Results Organization

### Output Directory Structure

```
Works/
├── {apk_name}_{timestamp}/
│   ├── Dynamic Analysis/              # MobSF dynamic analysis results
│   │   ├── mobsf_report.json         # Complete MobSF analysis
│   │   ├── network_traffic.json      # Network monitoring data
│   │   └── runtime_analysis.json     # Behavioral analysis
│   ├── Files Processed for Working/   # Extracted and processed files
│   │   ├── decompiled/               # JADX/Blutter output
│   │   ├── resources/                # Extracted resources
│   │   └── manifest/                 # Manifest analysis
│   ├── Fixes Requested/              # AI-generated vulnerability fixes
│   │   ├── vulnerability_fixes.json  # Structured fix data
│   │   └── fix_code/                 # Generated code patches
│   ├── Prompts Given to AI/          # AI analysis prompts
│   │   └── analysis_prompts.txt      # Sent prompts for transparency
│   └── Response By AI/               # AI analysis responses
│       ├── vulnerability_analysis.json
│       └── detailed_responses.txt
```

### Report Types

**Vulnerability Summary:**
- High-level security assessment
- Risk categorization and scoring
- Executive summary of findings
- Remediation priority matrix

**Detailed Analysis:**
- File-by-file vulnerability breakdown
- Code snippets with vulnerability context
- Technical explanation of security issues
- Line-by-line analysis results

**Fix Recommendations:**
- AI-generated patch suggestions
- Implementation guidance
- Alternative solution approaches
- Testing recommendations

**Dynamic Results (if enabled):**
- Runtime behavior analysis
- Network traffic security assessment
- Component interaction patterns
- Real-time vulnerability validation

### File Formats

**JSON Format:**
- Structured data for integration
- Machine-readable vulnerability data
- API-friendly format for automation
- Standard vulnerability schema

**Human-readable Reports:**
- Clear vulnerability descriptions
- Step-by-step fix instructions
- Code examples and explanations
- Executive summaries

**Generated Code:**
- Ready-to-use patch files
- Commented fix implementations
- Alternative solution approaches
- Integration instructions

</details>

<details>
<summary>🔧 Advanced Configuration</summary>

## Framework-Specific Configuration

### React Native Enhanced Analysis

**Prerequisites:**
- Node.js (v14+) and npm
- Internet connection for tool installation

**Enhanced Features:**
```bash
# Enable enhanced analysis
lu77u-mobilesec app.apk --type react-native --enhanced-rn
```

**Capabilities:**
- **Bundle Decompilation**: Converts minified JavaScript to readable code
- **Module Resolution**: Individual React Native module analysis
- **Advanced Patterns**: Bridge vulnerability detection
- **Context Preservation**: Maintains function and component context

**Tool Integration:**
- **react-native-decompiler**: Automatic installation and usage
- **Bundle Processing**: Support for multiple bundle formats
- **Source Map Support**: When available, uses source maps for accuracy

### Flutter Analysis Configuration

**Blutter Integration:**
- **Automatic Setup**: Tool handles Blutter installation
- **Dart Recovery**: Extracts Dart source from compiled Flutter apps
- **Asset Processing**: Flutter-specific resource extraction

### Java/Kotlin Analysis Options

**JADX Configuration:**
- **Decompilation Options**: Optimized settings for security analysis
- **Resource Extraction**: Complete APK content extraction
- **Multi-threading**: Parallel processing for large APKs

### MobSF Configuration

**Server Setup:**
```bash
# Custom MobSF server URL
export MOBSF_URL="http://your-mobsf-server:8000"

# API key configuration
export MOBSF_API_KEY="your-api-key"
```

**Analysis Options:**
- **Static + Dynamic**: Combined analysis mode
- **Dynamic Only**: Runtime-focused testing
- **Custom Timeout**: Configurable analysis duration

</details>

<details>
<summary>🐛 Troubleshooting</summary>

## Common Issues & Solutions

### Installation Issues

**Problem: JADX not found**
```bash
# macOS
brew install jadx

# Linux - Download from releases
wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.4.7.zip
unzip jadx-1.4.7.zip -d /opt/jadx
sudo ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

# Windows - Download and add to PATH
```

**Problem: Node.js required for React Native**
```bash
# macOS
brew install node

# Linux
sudo apt install nodejs npm

# Windows
choco install nodejs
```

**Problem: Java not found**
```bash
# Install OpenJDK 11+
brew install openjdk@11    # macOS
sudo apt install openjdk-11-jdk    # Linux
choco install openjdk    # Windows
```

### Analysis Issues

**Problem: APK parsing errors**
- Verify APK file integrity
- Check file permissions (readable)
- Use `--debug` flag for detailed error information
- Ensure APK is a valid Android application

**Problem: Decompilation failures**
- Large APKs may require more memory
- Corrupted APKs cannot be processed
- Some obfuscated APKs may have limited decompilation success
- Try different analysis types if auto-detection fails

**Problem: Framework detection issues**
- Use `--type` flag to force specific framework
- Check if APK contains expected framework files
- Some hybrid apps may need manual type specification

### MobSF Integration Issues

**Problem: MobSF connection fails**
- Verify MobSF server is running (`http://localhost:8000`)
- Check API key is correct
- Ensure network connectivity to MobSF server
- Verify MobSF version compatibility

**Problem: Dynamic analysis timeout**
- Increase timeout in MobSF settings
- Check device/emulator connectivity
- Ensure sufficient system resources

### AI Issues

**Problem: Groq API errors**
- Verify `GROQ_API_KEY` environment variable
- Check internet connectivity
- Ensure API quota is available
- Validate API key permissions

**Problem: Ollama not responding**
- Check if Ollama service is running: `ollama list`
- Verify DeepSeek Coder model: `ollama pull deepseek-coder:6.7b`
- Restart Ollama service: `ollama serve`
- Check system resources (RAM requirements)

**Problem: AI analysis slow**
- For Groq: Check internet speed and API limits
- For Ollama: Ensure sufficient RAM (8GB+ recommended)
- Use `--debug` to monitor analysis progress

### Performance Issues

**Problem: Long analysis times**
- Large APKs require more processing time
- Dynamic analysis adds significant time
- Enhanced React Native analysis is slower but more accurate
- Use selective analysis types for faster results

**Problem: Memory issues**
- Increase Java heap size for JADX
- Close other applications during analysis
- Use 64-bit Java installation
- Consider analyzing smaller APK subsets

### File Permission Issues

**Problem: Cannot write output files**
- Check write permissions in current directory
- Ensure sufficient disk space
- Verify user permissions for output location

</details>

<details>
<summary>🤝 Contributing</summary>

## Development & Contributions

### Development Setup

```bash
# Clone repository
git clone https://github.com/sam-mg/lu77U-MobileSec.git
cd lu77U-MobileSec

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Install in development mode
pip install -e .

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
flake8 lu77u_mobilesec/
black lu77u_mobilesec/
mypy lu77u_mobilesec/
```

### Code Style & Standards

- **Black**: Code formatting (line length: 88)
- **Flake8**: Linting and style checking
- **MyPy**: Static type checking
- **Pytest**: Unit and integration testing

### Project Structure

```
lu77u_mobilesec/
├── ai/                    # AI provider integrations
│   ├── processors/        # AI analysis processors
│   └── providers/         # Groq, Ollama implementations
├── cli/                   # Command-line interface
├── constants/             # Framework definitions, patterns
├── core/                  # Core analysis engine
│   ├── analyzers/         # Framework-specific analyzers
│   └── detectors/         # Framework detection logic
├── system/                # System validation and setup
├── tools/                 # External tool integrations
│   ├── android_tools/     # Android SDK utilities
│   ├── decompilers/       # JADX, Blutter, RN decompiler
│   └── mobsf_scripts/     # MobSF API integration
└── utils/                 # Utility functions
    ├── config/            # Configuration management
    ├── file_system/       # File operations
    └── helpers/           # Helper functions
```

### Contributing Guidelines

1. **Fork the Repository**
   - Create personal fork on GitHub
   - Clone fork locally for development

2. **Create Feature Branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```

3. **Make Changes**
   - Follow existing code style
   - Add tests for new functionality
   - Update documentation as needed

4. **Test Changes**
   ```bash
   # Run tests
   pytest

   # Run linting
   flake8 lu77u_mobilesec/
   black lu77u_mobilesec/ --check

   # Type checking
   mypy lu77u_mobilesec/
   ```

5. **Commit Changes**
   ```bash
   git add .
   git commit -m "Add amazing feature"
   ```

6. **Push to Branch**
   ```bash
   git push origin feature/amazing-feature
   ```

7. **Open Pull Request**
   - Provide clear description of changes
   - Reference any related issues
   - Ensure CI checks pass

### Areas for Contribution

**New Framework Support:**
- Xamarin applications
- Ionic/Cordova apps
- Unity mobile games
- Progressive Web Apps (PWA)

**Vulnerability Patterns:**
- Additional security detection rules
- Framework-specific vulnerability patterns
- OWASP Mobile Top 10 implementations
- Custom vulnerability definitions

**AI Integrations:**
- Additional LLM providers (OpenAI, Anthropic)
- Custom model fine-tuning
- Specialized security models
- Local model optimizations

**Tool Integrations:**
- Additional decompilers
- Static analysis tools
- Dynamic analysis platforms
- CI/CD pipeline integrations

**Documentation:**
- Tutorial content
- Video guides
- Translations
- Best practices guides

**Testing:**
- Expanded test coverage
- Performance benchmarks
- Integration test scenarios
- Sample APK creation

### Development Tips

- Use `--debug` flag extensively during development
- Test with various APK types and sizes
- Ensure cross-platform compatibility
- Add logging for debugging complex issues
- Follow existing error handling patterns

</details>

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Sam MG Harish (lu77_u)**
- Email: sammgharish@gmail.com
- GitHub: [@sam-mg](https://github.com/sam-mg)

---

## ⭐ Support

If you find this tool helpful, please consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs and issues
- 💡 Suggesting new features
- 🤝 Contributing to the project

<p align="right">
    <img src="https://wakatime.com/badge/user/f5bf5341-405c-480f-bd76-40a5c1a8ada9/project/f2697ac6-8530-46a0-ae2c-01eb4f730bdb.svg?style=for-the-badge"/>
</p>
