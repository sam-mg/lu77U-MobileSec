# Contributing to lu77U-MobileSec

Welcome to the lu77U-MobileSec project! We're excited that you're interested in contributing to this advanced mobile security analysis platform. This guide will help you get started with contributing effectively.

---

## 🚀 Quick Start for Contributors

1. **Fork the repository** and create your branch from `main`
2. **Set up development environment** (see detailed setup below)
3. **Make your changes** with proper testing
4. **Ensure code quality** meets our standards
5. **Submit a pull request** with clear documentation

---

## 📋 What We're Looking For

We welcome all types of contributions:

- 🐛 **Bug Reports & Fixes**: Help us identify and resolve issues
- ✨ **New Features**: Framework support, analysis capabilities, tool integrations
- 📖 **Documentation**: Improvements, tutorials, examples, translations
- 🧪 **Testing**: Test coverage, performance tests, integration scenarios
- 🔍 **Security Patterns**: New vulnerability detection rules and patterns
- 🤖 **AI Integrations**: Additional LLM providers and analysis improvements

---

<details>
<summary>🛠️ Development Environment Setup</summary>

## Prerequisites

Before setting up the development environment, ensure you have:

- **Python 3.8+** (recommended: 3.9+)
- **Git** for version control
- **Java 11+** (OpenJDK recommended)
- **Node.js 14+** (for React Native enhanced analysis)
- **JADX** (for Java/Kotlin decompilation)

## Development Setup

### 1. Clone and Fork

```bash
# Fork the repository on GitHub first, then clone your fork
git clone https://github.com/your-username/lu77U-MobileSec.git
cd lu77U-MobileSec

# Add upstream remote for keeping in sync
git remote add upstream https://github.com/sam-mg/lu77U-MobileSec.git
```

### 2. Python Environment Setup

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install in development mode with all dependencies
pip install -e ".[dev]"

# Install additional development tools
pip install pre-commit pytest-cov black flake8 mypy
```

### 3. Install External Dependencies

```bash
# Run system doctor to check and install missing dependencies
python -m lu77u_mobilesec doctor --debug

# This will check and guide you through installing:
# - JADX (Java APK decompiler)
# - Node.js and npm (for React Native analysis)
# - Android SDK tools (optional)
# - Ollama (for local AI analysis)
```

### 4. Pre-commit Hooks (Recommended)

```bash
# Install pre-commit hooks for automatic code formatting
pre-commit install

# Test the hooks
pre-commit run --all-files
```

### 5. Verify Installation

```bash
# Test basic functionality
python -m lu77u_mobilesec --help

# Run system doctor
python -m lu77u_mobilesec doctor

# Run test suite
pytest tests/ -v
```

</details>

<details>
<summary>🧪 Testing & Code Quality</summary>

## Testing Guidelines

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage report
pytest tests/ --cov=lu77u_mobilesec --cov-report=html

# Run specific test file
pytest tests/test_framework_detection.py -v

# Run specific test function
pytest tests/test_basic.py::test_version_info -v

# Run tests with live output
pytest tests/ -s

# Run tests in parallel (if pytest-xdist is installed)
pytest tests/ -n auto
```

### Writing Tests

Follow these guidelines when writing tests:

```python
import pytest
from unittest.mock import patch, MagicMock
from lu77u_mobilesec.core.detectors.framework_detector import FrameworkDetector

class TestFrameworkDetector:
    """Test cases for FrameworkDetector class"""
    
    def test_detect_react_native_app(self, sample_rn_apk):
        """Test React Native app detection with valid APK"""
        # Arrange
        detector = FrameworkDetector()
        
        # Act
        result = detector.detect_framework(sample_rn_apk)
        
        # Assert
        assert result == "react-native"
        assert detector.confidence > 0.8
    
    def test_detect_invalid_apk_raises_error(self):
        """Test that invalid APK raises appropriate error"""
        detector = FrameworkDetector()
        
        with pytest.raises(ValueError, match="Invalid APK file"):
            detector.detect_framework("invalid_file.txt")
    
    @patch('lu77u_mobilesec.tools.decompilers.jadx_wrapper.JADXWrapper')
    def test_java_analysis_with_mocked_jadx(self, mock_jadx):
        """Test Java analysis with mocked JADX decompiler"""
        # Setup mock
        mock_jadx.return_value.decompile.return_value = True
        
        # Test logic here
        pass
```

### Test Structure

- **Unit Tests**: Test individual functions and classes
- **Integration Tests**: Test component interactions
- **End-to-End Tests**: Test complete workflows
- **Performance Tests**: Test analysis speed and memory usage

### Test Data

```bash
# Sample APKs for testing (if available)
tests/
├── fixtures/
│   ├── sample_java_app.apk
│   ├── sample_react_native_app.apk
│   └── sample_flutter_app.apk
├── mocks/
│   └── mock_responses.json
└── test_*/
    └── test_*.py
```

## Code Quality Standards

### Code Formatting

```bash
# Format code with Black
black lu77u_mobilesec/ tests/

# Check formatting without changes
black lu77u_mobilesec/ tests/ --check

# Format specific file
black lu77u_mobilesec/core/analyzers/java_kotlin_analyzer.py
```

### Linting

```bash
# Lint with flake8
flake8 lu77u_mobilesec/ --count --statistics

# Lint specific directory
flake8 lu77u_mobilesec/ai/ --show-source

# Check for specific error types
flake8 lu77u_mobilesec/ --select=E9,F63,F7,F82
```

### Type Checking

```bash
# Type check with mypy
mypy lu77u_mobilesec/

# Type check specific module
mypy lu77u_mobilesec/core/analyzers/

# Generate type coverage report
mypy lu77u_mobilesec/ --html-report mypy_report/
```

### Code Style Guidelines

- **Follow PEP 8**: Python style guide compliance
- **Use Type Hints**: Add type annotations for function parameters and returns
- **Write Docstrings**: Document all public functions, classes, and modules
- **Keep Functions Small**: Aim for functions under 50 lines
- **Use Meaningful Names**: Clear, descriptive variable and function names
- **Handle Errors Gracefully**: Proper exception handling and user feedback

### Example Code Style

```python
from typing import Optional, List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class VulnerabilityAnalyzer:
    """
    Analyzes code for security vulnerabilities using AI-powered detection.
    
    This class provides methods for scanning different types of mobile
    applications and generating detailed vulnerability reports.
    """
    
    def __init__(self, ai_provider: str = "ollama", debug: bool = False) -> None:
        """
        Initialize the vulnerability analyzer.
        
        Args:
            ai_provider: AI provider to use ('groq' or 'ollama')
            debug: Enable debug logging
        """
        self.ai_provider = ai_provider
        self.debug = debug
        self._setup_logging()
    
    def analyze_code_patterns(
        self, 
        code_content: str, 
        framework_type: str
    ) -> List[Dict[str, Any]]:
        """
        Analyze code content for vulnerability patterns.
        
        Args:
            code_content: Source code to analyze
            framework_type: Type of framework ('java', 'react-native', 'flutter')
            
        Returns:
            List of vulnerability findings with details
            
        Raises:
            ValueError: If framework_type is not supported
            AnalysisError: If analysis fails
        """
        if framework_type not in ['java', 'react-native', 'flutter']:
            raise ValueError(f"Unsupported framework: {framework_type}")
        
        try:
            vulnerabilities = self._scan_for_patterns(code_content, framework_type)
            return self._enrich_vulnerabilities(vulnerabilities)
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            raise AnalysisError(f"Failed to analyze code: {e}")
    
    def _setup_logging(self) -> None:
        """Setup logging configuration based on debug setting."""
        level = logging.DEBUG if self.debug else logging.INFO
        logging.basicConfig(level=level)
```

</details>

<details>
<summary>📝 Pull Request Process</summary>

## Before Submitting a Pull Request

### 1. Preparation Checklist

- [ ] **Code is tested**: All new functionality has corresponding tests
- [ ] **Tests pass**: `pytest tests/` runs without failures
- [ ] **Code is formatted**: `black` and `flake8` pass without errors
- [ ] **Types are checked**: `mypy` passes without type errors
- [ ] **Documentation updated**: README, docstrings, and comments are current
- [ ] **CHANGELOG updated**: Add entry to CHANGELOG.md for significant changes

### 2. Branch Strategy

```bash
# Create feature branch from main
git checkout main
git pull upstream main
git checkout -b feature/amazing-new-feature

# Work on your changes
git add .
git commit -m "Add amazing new feature"

# Keep branch updated
git fetch upstream
git rebase upstream/main

# Push to your fork
git push origin feature/amazing-new-feature
```

### 3. Commit Message Guidelines

Follow conventional commit format:

```
type(scope): brief description

Detailed explanation of what changed and why.
Include any breaking changes or migration notes.

Fixes #123
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `perf`: Performance improvements
- `chore`: Maintenance tasks

**Examples:**
```
feat(analyzer): add Flutter widget vulnerability detection

Add comprehensive scanning for Flutter widget security patterns
including platform channel vulnerabilities and asset security.

- Implement WidgetSecurityScanner class
- Add 15 new vulnerability patterns
- Include test cases for all patterns

Fixes #145
```

```
fix(cli): resolve crash when APK file not found

Handle FileNotFoundError gracefully and provide user-friendly
error message when specified APK file doesn't exist.

Fixes #156
```

## Pull Request Template

When creating a PR, use this template:

```markdown
## Description
Brief description of the changes in this PR.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## Framework Support
- [ ] Java/Kotlin APKs
- [ ] React Native APKs
- [ ] Flutter APKs
- [ ] Cross-platform changes

## Testing
- [ ] I have tested my changes locally
- [ ] I have run the test suite (`pytest tests/`)
- [ ] I have tested with sample APKs
- [ ] I have run `lu77u-mobilesec doctor` to verify dependencies

## Code Quality
- [ ] Code follows project style guidelines
- [ ] Self-review of code completed
- [ ] Code is well-documented with docstrings
- [ ] CHANGELOG.md updated (for significant changes)

## Screenshots (if applicable)
Add screenshots of new features or UI changes.

## Additional Notes
Any additional information, concerns, or considerations.
```

## Review Process

1. **Automated Checks**: CI/CD pipeline runs tests and quality checks
2. **Code Review**: Maintainers review code for quality and functionality
3. **Testing**: Changes are tested on multiple platforms if applicable
4. **Approval**: At least one maintainer approval required
5. **Merge**: Squash and merge or rebase merge based on change type

</details>

<details>
<summary>🐛 Bug Reports</summary>

## Reporting Bugs

### Before Reporting

1. **Search existing issues** to avoid duplicates
2. **Try the latest version** to see if the issue is already fixed
3. **Check documentation** to ensure it's not expected behavior
4. **Run system doctor** (`lu77u-mobilesec doctor`) to verify setup

### Bug Report Template

```markdown
**Bug Description**
A clear and concise description of the bug.

**Steps to Reproduce**
1. Run command: `lu77u-mobilesec sample.apk --type react-native`
2. Wait for analysis to complete
3. Check output directory
4. See error in console

**Expected Behavior**
What you expected to happen.

**Actual Behavior**
What actually happened. Include error messages and stack traces.

**Environment**
- OS: [e.g., Windows 10, macOS 13, Ubuntu 22.04]
- Python version: [e.g., 3.9.7]
- lu77U-MobileSec version: [e.g., 1.0.0]
- JADX version: [e.g., 1.4.7]
- Node.js version: [e.g., 18.16.0] (if applicable)

**APK Information** (if applicable)
- APK size: [e.g., 50MB]
- Framework type: [e.g., React Native]
- Any special characteristics: [e.g., obfuscated, large bundle]

**Additional Context**
Add any other context about the problem here.
```

### Security Issues

For security vulnerabilities in lu77U-MobileSec itself:
- **DO NOT** open a public issue
- Email: sammgharish@gmail.com with subject "[SECURITY]"
- See [SECURITY.md](SECURITY.md) for details

</details>

<details>
<summary>💡 Feature Requests</summary>

## Proposing New Features

### Before Requesting

1. **Check existing issues** and discussions
2. **Review roadmap** in CHANGELOG.md
3. **Consider scope and complexity**
4. **Think about maintenance burden**

### Feature Request Template

```markdown
**Feature Description**
A clear and concise description of the feature you'd like to see.

**Use Case**
Describe the use case and why this feature would be valuable.
Who would benefit from this feature?

**Proposed Solution**
Describe your preferred solution approach if you have ideas.

**Alternative Solutions**
Describe any alternative solutions you've considered.

**Framework Impact**
- [ ] Affects Java/Kotlin analysis
- [ ] Affects React Native analysis  
- [ ] Affects Flutter analysis
- [ ] Cross-framework feature
- [ ] Infrastructure/tooling change

**Additional Context**
Add any other context, mockups, or examples about the feature.
```

### Feature Categories

**High Priority Features:**
- New framework support (Xamarin, Ionic, etc.)
- Additional vulnerability patterns
- Enhanced AI integrations
- Performance optimizations

**Medium Priority Features:**
- UI/UX improvements
- Additional output formats
- CI/CD integrations
- Advanced configuration options

**Community Requests:**
- Documentation improvements
- Tutorial content
- Example projects
- Translation support

</details>

---

## 🏆 Areas for Contribution

### High Priority Contributions

#### 🔍 New Framework Support
- **Xamarin Applications**: Analysis of C# mobile apps
- **Ionic/Cordova**: Hybrid app analysis capabilities
- **Unity Mobile Games**: Game-specific security patterns
- **Progressive Web Apps**: PWA security assessment

#### 🛡️ Security Pattern Expansion
- **OWASP Mobile Top 10**: Complete implementation
- **Framework-Specific Patterns**: Advanced vulnerability detection
- **Custom Rule Engine**: User-defined security rules
- **Zero-Day Pattern Detection**: Emerging vulnerability patterns

#### 🤖 AI Integration Enhancements
- **Additional LLM Providers**: OpenAI, Anthropic, local models
- **Model Fine-tuning**: Security-specific model training
- **Context Improvement**: Better code context understanding
- **Multi-language Support**: Analysis in multiple languages

### Medium Priority Contributions

#### 🛠️ Tool Integrations
- **Additional Decompilers**: Support for more decompilation tools
- **Static Analysis Tools**: Integration with other security scanners
- **Dynamic Analysis**: More runtime analysis platforms
- **CI/CD Plugins**: GitHub Actions, Jenkins, GitLab CI

#### 📊 Reporting & Output
- **Advanced Report Formats**: PDF, XML, SARIF support
- **Dashboard Interface**: Web-based analysis dashboard
- **Database Integration**: Store and query analysis results
- **Trend Analysis**: Historical vulnerability tracking

#### ⚡ Performance Optimizations
- **Parallel Processing**: Multi-threaded analysis
- **Memory Optimization**: Reduced resource usage
- **Caching Systems**: Intelligent result caching
- **Incremental Analysis**: Delta analysis for changes

### Community Contributions

#### 📖 Documentation & Education
- **Tutorial Content**: Step-by-step guides
- **Video Tutorials**: Screen recordings and walkthroughs
- **Best Practices**: Security analysis best practices
- **Translation**: Multi-language documentation

#### 🧪 Testing & Quality
- **Test Coverage**: Expand automated testing
- **Performance Benchmarks**: Analysis speed metrics
- **Edge Case Testing**: Unusual APK handling
- **Integration Testing**: End-to-end scenarios

#### 🌍 Accessibility & Usability
- **Cross-Platform Support**: Enhanced Windows/Linux support
- **User Experience**: Improved CLI and error messages
- **Accessibility**: Support for screen readers and accessibility tools
- **Mobile Interface**: Mobile-friendly analysis interface

---

## 📚 Development Resources

### Project Architecture

```
lu77u_mobilesec/
├── ai/                     # AI provider integrations
│   ├── processors/         # Analysis and fix generation
│   │   ├── batch_processor.py
│   │   ├── fix_generator.py
│   │   ├── response_parser.py
│   │   └── vulnerability_analyzer.py
│   └── providers/          # LLM provider implementations
│       ├── base_provider.py
│       ├── groq_provider.py
│       └── ollama_provider.py
├── cli/                    # Command-line interface
│   ├── app.py             # Main CLI application
│   ├── arguments.py       # Argument parsing
│   ├── commands.py        # CLI commands
│   ├── interactive.py     # Interactive mode
│   └── interface.py       # User interface components
├── constants/              # Framework and pattern definitions
│   ├── file_patterns.py   # File pattern detection
│   ├── frameworks.py      # Framework definitions
│   ├── severity_levels.py # Vulnerability severity
│   └── vulnerabilities.py # Vulnerability patterns
├── core/                   # Core analysis engine
│   ├── analyzers/         # Framework-specific analyzers
│   │   ├── flutter_analyzer.py
│   │   ├── java_kotlin_analyzer.py
│   │   ├── mobsf_analyzer.py
│   │   └── react_native_analyzer.py
│   ├── detectors/         # Framework detection
│   │   └── framework_detector.py
│   ├── orchestrator.py    # Analysis coordination
│   └── vulnerability/     # Vulnerability processing
│       ├── patterns.py
│       ├── reporting.py
│       ├── scanner.py
│       └── severity.py
├── system/                 # System management
│   ├── doctor/            # Dependency management
│   │   └── main_doctor.py
│   └── validators/        # Environment validation
│       ├── detailed_checker.py
│       ├── path_checker.py
│       ├── tool_checker.py
│       └── version_checker.py
├── tools/                  # External tool integrations
│   ├── android_tools/     # Android SDK tools
│   │   ├── avd_installer.py
│   │   └── manifest_parser.py
│   ├── decompilers/       # Decompiler integrations
│   │   ├── blutter_wrapper.py
│   │   ├── jadx_wrapper.py
│   │   └── react_native_decompiler.py
│   └── mobsf_scripts/     # MobSF integration
│       └── mobsf_api.py
└── utils/                  # Utility functions
    ├── config/            # Configuration management
    │   ├── api_keys.py
    │   └── manager.py
    ├── file_system/       # File operations
    │   ├── manager.py
    │   └── output_organizer.py
    └── helpers/           # Helper functions
        ├── string_utils.py
        ├── time_utils.py
        └── validation.py
```

### Key Design Patterns

- **Modular Architecture**: Clear separation of concerns
- **Plugin System**: Easy framework and tool integration
- **Factory Pattern**: Dynamic analyzer selection
- **Observer Pattern**: Progress tracking and logging
- **Strategy Pattern**: Different analysis strategies per framework

### Coding Standards

- **Type Safety**: Use type hints throughout
- **Error Handling**: Comprehensive exception handling
- **Logging**: Structured logging with appropriate levels
- **Configuration**: Environment-based configuration
- **Testing**: High test coverage with meaningful tests

---

## 🤝 Community Guidelines

### Code of Conduct

- **Be Respectful**: Treat all contributors with respect
- **Be Constructive**: Provide helpful feedback and suggestions
- **Be Patient**: Remember that everyone has different experience levels
- **Be Professional**: Maintain professional communication

### Getting Help

- **GitHub Discussions**: For questions and general discussion
- **GitHub Issues**: For bugs and feature requests
- **Documentation**: Check README and code documentation
- **Code Examples**: Look at existing code for patterns

### Recognition

Contributors will be recognized through:
- **README Contributors Section**: Listed in project README
- **Release Notes**: Mentioned in release announcements
- **Commit History**: Permanent record of contributions
- **Special Recognition**: Outstanding contributions highlighted

---

## 📄 License & Legal

By contributing to lu77U-MobileSec, you agree that:

- Your contributions will be licensed under the **Apache License 2.0**
- You have the right to submit the contributions
- Your contributions don't violate any third-party rights
- You understand the project's license terms

---

## 📞 Contact & Questions

### Getting Support

- **GitHub Discussions**: https://github.com/sam-mg/lu77U-MobileSec/discussions
- **GitHub Issues**: https://github.com/sam-mg/lu77U-MobileSec/issues
- **Email**: sammgharish@gmail.com (for sensitive issues)

### Response Times

- **GitHub Issues**: 24-48 hours for initial response
- **Pull Requests**: 2-7 days for review
- **Security Issues**: 24 hours for initial response
- **General Questions**: 1-3 days via discussions

---

**Thank you for contributing to lu77U-MobileSec! 🚀**

Your contributions help make mobile security analysis more accessible and effective for developers and security professionals worldwide.
