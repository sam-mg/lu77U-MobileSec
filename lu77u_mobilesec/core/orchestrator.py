#!/usr/bin/env python3
"""
Main orchestrator for lu77U-MobileSec

Coordinates the analysis workflow between different framework-specific analyzers
based on APK type detection.
"""

import os
import time
from typing import Optional, Dict, Any
from pathlib import Path

from ..utils.config.api_keys import load_groq_api_key
from ..utils.helpers.time_utils import start_analysis_timer, end_analysis_timer, format_duration
from ..utils.helpers.validation import validate_apk_path
from ..system.validators.tool_checker import ensure_ollama_running


class MobileSecAnalyzer:
    """
    Main orchestrator class for mobile security analysis
    
    Coordinates between different analyzers based on APK type detection
    """
    
    def __init__(self, debug=False, llm_preference=None):
        """Initialize the main analyzer"""
        # Auto-load API key from config
        load_groq_api_key()
        
        self.debug = debug
        self.llm_preference = llm_preference or 'ollama'
        
        # Timer for analysis duration
        self.analysis_start_time = None
        
        # Set LLM preference
        self.use_local_llm = (self.llm_preference == 'ollama')
        self.llm_choice_made = True  # Mark as explicitly set
        
        # Directory structure for current analysis
        self.apk_name = None
        self.analysis_directories = None
        self.analysis_timestamp = None
        
        if self.debug:
            llm_name = "Ollama (Deepseek Coder-6.7B)" if self.llm_preference == 'ollama' else "GROQ API"
            print(f"🐛 DEBUG: LLM preference set to: {llm_name}")
        
        # Initialize analyzers (lazy loading to avoid circular imports)
        self._detector = None
        self._java_analyzer = None
        self._react_native_analyzer = None
        self._flutter_analyzer = None
        self._mobsf_analyzer = None
    
    @property
    def detector(self):
        """Lazy load the framework detector"""
        if self._detector is None:
            from .detectors.framework_detector import FrameworkDetector
            self._detector = FrameworkDetector(debug=self.debug)
            self._detector.use_local_llm = self.use_local_llm
            self._detector.llm_choice_made = self.llm_choice_made
        return self._detector
    
    @property
    def java_analyzer(self):
        """Lazy load the Java/Kotlin analyzer"""
        if self._java_analyzer is None:
            from .analyzers.java_kotlin_analyzer import JavaKotlinAnalyzer
            self._java_analyzer = JavaKotlinAnalyzer(orchestrator=self, debug=self.debug)
        return self._java_analyzer
    
    @property
    def react_native_analyzer(self):
        """Lazy load the React Native analyzer"""
        if self._react_native_analyzer is None:
            from .analyzers.react_native_analyzer import ReactNativeAnalyzer
            self._react_native_analyzer = ReactNativeAnalyzer(orchestrator=self, debug=self.debug)
        return self._react_native_analyzer
    
    @property
    def flutter_analyzer(self):
        """Lazy load the Flutter analyzer"""
        if self._flutter_analyzer is None:
            from .analyzers.flutter_analyzer import FlutterAnalyzer
            self._flutter_analyzer = FlutterAnalyzer(detector=self.detector)
        return self._flutter_analyzer
    
    @property
    def mobsf_analyzer(self):
        """Lazy load the MobSF analyzer"""
        if self._mobsf_analyzer is None:
            from .analyzers.mobsf_analyzer import MobSFAnalyzer
            # Pass the current APK path if available, otherwise use default
            apk_path = getattr(self, '_current_apk_path', None)
            self._mobsf_analyzer = MobSFAnalyzer(apk_path=apk_path, debug=self.debug)
        return self._mobsf_analyzer
    
    def debug_print(self, message):
        """Print debug messages if debug mode is enabled"""
        if self.debug:
            print(f"🐛 DEBUG: {message}")
    
    def validate_apk_file(self, apk_path: str) -> bool:
        """Validate that the APK file exists and is readable"""
        is_valid, error_msg = validate_apk_path(apk_path)
        
        if not is_valid:
            print(f"❌ {error_msg}")
            return False
        
        file_size = os.path.getsize(apk_path)
        print(f"✅ APK file validated: {apk_path} ({file_size:,} bytes)")
        
        # Start the analysis timer once APK is validated
        self.analysis_start_time = start_analysis_timer()
        print(f"⏱️  Analysis started at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        return True
    
    async def detect_and_analyze(self, apk_path: str, force_type: Optional[str] = None, fix_vulnerabilities: bool = False, run_dynamic_analysis: bool = False) -> bool:
        """
        Detect APK type and run appropriate analysis
        
        Args:
            apk_path: Path to the APK file
            force_type: Force analysis type ('java', 'react-native', 'flutter')
            fix_vulnerabilities: Whether to prompt for and generate fixes
            run_dynamic_analysis: Whether to run MobSF dynamic analysis
        
        Returns:
            bool: True if analysis completed successfully
        """
        print(f"\n🔍 Analyzing APK: {os.path.basename(apk_path)}")
        print("=" * 60)
        
        # Validate APK file
        if not self.validate_apk_file(apk_path):
            # Timer is only started if validation succeeds, so no need to end it here
            return False
        
        # Set up structured analysis directories
        self.setup_analysis_directories(apk_path)
        
        # Store current APK path for MobSF analyzer
        self._current_apk_path = apk_path
        
        # Check and start Ollama service if needed
        if not ensure_ollama_running(self.use_local_llm):
            duration = end_analysis_timer(self.analysis_start_time)
            print("⚠️  AI analysis will be skipped due to Ollama connection issues.")
            print("💡 To enable AI analysis:")
            print("   • Run: ollama serve")
            print("   • Or use GROQ API with: --llm groq")
            print("   • Or run: lu77u-mobilesec doctor")
            print("📝 Continuing with pattern-based analysis only...")
            # Don't return False here - continue with pattern-based analysis
        
        # Detect APK type (unless forced)
        if force_type:
            apk_type = force_type
            print(f"🎯 Forced analysis type: {apk_type}")
            self.debug_print(f"Using forced APK type: {apk_type}")
        else:
            self.debug_print("Starting APK type detection...")
            apk_type = self.detector.detect_apk_type(apk_path)
            self.debug_print(f"Detected APK type: {apk_type}")
            if not apk_type:
                duration = end_analysis_timer(self.analysis_start_time)
                print("❌ Could not determine APK type")
                print(f"⏱️  Total time taken before failure: {format_duration(duration)}")
                return False
        
        # Run appropriate analyzer
        try:
            self.debug_print(f"Routing to analyzer for APK type: {apk_type}")
            if apk_type == 'flutter':
                print("\n🚀 Running Flutter APK Analysis...")
                self.debug_print("Calling Flutter analyzer")
                await self.flutter_analyzer.analyze_flutter_apk(
                    apk_path,
                    end_timer_callback=lambda: end_analysis_timer(self.analysis_start_time),
                    format_duration_callback=format_duration,
                    fix_vulnerabilities=fix_vulnerabilities
                )
                
            elif apk_type == 'react-native':
                print("\n🚀 Running React Native APK Analysis...")
                self.debug_print("Calling React Native analyzer")
                await self.react_native_analyzer.analyze_react_native_apk(
                    apk_path,
                    fix_vulnerabilities=fix_vulnerabilities
                )
                
            elif apk_type in ['java', 'kotlin', 'java_kotlin']:
                print("\n🚀 Running Java/Kotlin APK Analysis...")
                self.debug_print("Calling Java/Kotlin analyzer")
                await self.java_analyzer.analyze_java_kotlin_apk(
                    apk_path,
                    fix_vulnerabilities=fix_vulnerabilities
                )
                
            else:
                print(f"❌ Unsupported APK type: {apk_type}")
                print("Supported types: java, kotlin, java_kotlin, react-native, flutter")
                
                # End timer even for unsupported APKs
                duration = end_analysis_timer(self.analysis_start_time)
                print(f"\n⏱️  Total time taken to analyze this file: {format_duration(duration)}")
                return False
            
            # End timer only for non-Flutter analysis (Flutter handles its own timing)
            if apk_type != 'flutter':
                duration = end_analysis_timer(self.analysis_start_time)
                print(f"\n✅ {apk_type.title()} analysis completed successfully!")
                print(f"⏱️  Total time taken to analyze this file: {format_duration(duration)}")
            else:
                duration = 0  # Flutter handles its own timing
            
            # Run dynamic analysis if requested
            dynamic_analysis_result = "Not requested"
            dynamic_analysis_details = {}
            
            if run_dynamic_analysis:
                print("\n🚀 Starting MobSF Dynamic Analysis...")
                try:
                    # Update the MobSF analyzer with the current APK path
                    self._current_apk_path = apk_path
                    self.mobsf_analyzer.apk_path = apk_path
                    
                    # Initialize MobSF analyzer with the APK path
                    mobsf_results = self.mobsf_analyzer.run_dynamic_analysis(
                        save_results=True,
                        analysis_directories=self.analysis_directories,
                        apk_name=self.apk_name
                    )
                    
                    if mobsf_results:
                        # Calculate success metrics
                        passed_tests = sum(1 for r in mobsf_results.values() if r['status'] == 'PASS')
                        failed_tests = sum(1 for r in mobsf_results.values() if r['status'] == 'FAIL')
                        total_tests = passed_tests + failed_tests
                        
                        if total_tests > 0:
                            success_rate = (passed_tests / total_tests) * 100
                            dynamic_analysis_result = f"Completed ({success_rate:.1f}% success rate)"
                            dynamic_analysis_details = {
                                'total_tests': total_tests,
                                'passed_tests': passed_tests,
                                'failed_tests': failed_tests,
                                'success_rate': f"{success_rate:.1f}%",
                                'test_results': mobsf_results
                            }
                        else:
                            dynamic_analysis_result = "Completed (no tests executed)"
                        
                        # Save dynamic analysis results to structured output
                        if self.analysis_directories:
                            from ..utils.file_system.output_organizer import save_dynamic_analysis
                            save_dynamic_analysis(
                                mobsf_results, 
                                self.apk_name, 
                                self.analysis_directories
                            )
                            print("📁 Dynamic analysis results saved to structured output directory")
                    else:
                        dynamic_analysis_result = "Failed to execute"
                        
                except Exception as e:
                    print(f"❌ Dynamic analysis failed: {e}")
                    dynamic_analysis_result = f"Failed: {str(e)}"
                    if self.debug:
                        import traceback
                        traceback.print_exc()
            
            # Finalize analysis with summary creation
            analysis_stats = {
                'framework_type': apk_type,
                'duration': format_duration(duration) if duration else 'Handled by analyzer',
                'timestamp': self.analysis_timestamp,
                'static_analysis': 'Completed',
                'ai_analysis': 'Completed' if not self.use_local_llm or ensure_ollama_running(self.use_local_llm) else 'Skipped',
                'dynamic_analysis': dynamic_analysis_result,
                'total_vulnerabilities': 'See individual reports',
                'high_severity': 'See individual reports',
                'medium_severity': 'See individual reports', 
                'low_severity': 'See individual reports'
            }
            
            # Add dynamic analysis details if available
            if dynamic_analysis_details:
                analysis_stats['dynamic_analysis_details'] = dynamic_analysis_details
                
            self.finalize_analysis(analysis_stats)
            
            return True
            
        except Exception as e:
            # End timer even on error
            duration = end_analysis_timer(self.analysis_start_time)
            print(f"❌ Analysis failed: {e}")
            print(f"⏱️  Total time taken before failure: {format_duration(duration)}")
            
            # Still create analysis structure for debugging
            if self.analysis_directories:
                analysis_stats = {
                    'framework_type': 'Unknown',
                    'duration': format_duration(duration),
                    'timestamp': self.analysis_timestamp,
                    'static_analysis': 'Failed',
                    'ai_analysis': 'Failed',
                    'dynamic_analysis': 'Failed',
                    'total_vulnerabilities': 0,
                    'high_severity': 0,
                    'medium_severity': 0,
                    'low_severity': 0,
                    'error': str(e)
                }
                self.finalize_analysis(analysis_stats)
            
            import traceback
            traceback.print_exc()
            return False
    
    def debug_test_detection(self, apk_path: str):
        """Debug function to test APK type detection"""
        print(f"\n🐛 DEBUG: Testing APK detection for {os.path.basename(apk_path)}")
        print("=" * 50)
        
        if not os.path.exists(apk_path):
            print("❌ APK file not found")
            return
            
        # Test detection
        apk_type = self.detector.detect_apk_type(apk_path)
        print(f"✅ Detected type: {apk_type}")
        
        # Show routing logic
        if apk_type == 'flutter':
            print("🔀 Would route to: Flutter analyzer")
        elif apk_type == 'react-native':
            print("🔀 Would route to: React Native analyzer")
        elif apk_type in ['java', 'kotlin', 'java_kotlin']:
            print("🔀 Would route to: Java/Kotlin analyzer")
        else:
            print(f"❌ Would show unsupported type error: {apk_type}")
            
        # Show supported types
        print(f"📋 Supported types: Java, Kotlin, React Native, Flutter")
        
    def debug_show_status(self):
        """Debug function to show analyzer status"""
        print("\n🐛 DEBUG: Analyzer Status")
        print("=" * 30)
        print(f"Debug mode: {self.debug}")
        print(f"LLM preference: {self.llm_preference}")
        print(f"Use local LLM: {self.use_local_llm}")
        print(f"Detector loaded: {self._detector is not None}")
        print(f"Java analyzer loaded: {self._java_analyzer is not None}")
        print(f"Flutter analyzer loaded: {self._flutter_analyzer is not None}")
        print(f"React Native analyzer loaded: {self._react_native_analyzer is not None}")
        print(f"MobSF analyzer loaded: {self._mobsf_analyzer is not None}")
    
    def _ensure_llm_availability(self):
        """Ensure LLM is available, fallback to GROQ if Ollama fails"""
        if self.llm_preference == 'ollama':
            self.debug_print("Checking Ollama availability...")
            if not self._check_ollama_availability():
                self.debug_print("Ollama not available, falling back to GROQ")
                print("⚠️  Ollama not available, falling back to GROQ API")
                self.llm_preference = 'groq'
                self.use_local_llm = False
                # Update detector if already initialized
                if self._detector:
                    self._detector.use_local_llm = False
        
        # Load GROQ API key if using GROQ
        if self.llm_preference == 'groq':
            api_key = load_groq_api_key()
            if not api_key:
                print("❌ GROQ API key not found. Please set GROQ_API_KEY environment variable.")
                return False
            self.debug_print("GROQ API key loaded successfully")
        
        return True
    
    def _check_ollama_availability(self) -> bool:
        """Check if Ollama is available and has the required model"""
        try:
            import subprocess
            
            # Check if Ollama is installed
            result = subprocess.run(['ollama', '--version'], capture_output=True, text=True)
            if result.returncode != 0:
                self.debug_print("Ollama not installed")
                return False
            
            # Check if Ollama service is running or start it
            if not ensure_ollama_running():
                self.debug_print("Failed to start Ollama service")
                return False
            
            # Check if DeepSeek model is available
            result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
            if 'deepseek-coder:6.7b' not in result.stdout:
                self.debug_print("DeepSeek model not found")
                return False
            
            self.debug_print("Ollama and DeepSeek model available")
            return True
            
        except Exception as e:
            self.debug_print(f"Error checking Ollama: {e}")
            return False
    
    def setup_analysis_directories(self, apk_path: str) -> None:
        """Set up the structured analysis directories for the APK"""
        from ..utils.file_system.output_organizer import create_apk_analysis_structure
        from datetime import datetime
        
        # Extract APK name without extension
        apk_path_obj = Path(apk_path)
        self.apk_name = apk_path_obj.stem
        
        # Generate timestamp
        self.analysis_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create directory structure
        self.analysis_directories = create_apk_analysis_structure(
            self.apk_name, 
            self.analysis_timestamp
        )
        
        if self.debug:
            print(f"🐛 DEBUG: Analysis directories created for {self.apk_name}")
            for name, path in self.analysis_directories.items():
                print(f"🐛 DEBUG:   {name}: {path}")
    
    def get_analysis_directories(self) -> Optional[Dict[str, Path]]:
        """Get the current analysis directories"""
        return self.analysis_directories
    
    def finalize_analysis(self, analysis_stats: Dict[str, Any]) -> None:
        """Finalize analysis by creating summary and cleaning up"""
        if self.analysis_directories and self.apk_name:
            from ..utils.file_system.output_organizer import create_analysis_summary, output_organizer
            
            # Create analysis summary
            create_analysis_summary(
                self.analysis_directories, 
                self.apk_name, 
                analysis_stats
            )
            
            # Cleanup empty directories
            output_organizer.cleanup_empty_directories(self.analysis_directories)
            
            print(f"📋 Analysis finalized for {self.apk_name}")
