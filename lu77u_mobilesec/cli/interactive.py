#!/usr/bin/env python3
"""
Interactive CLI mode for lu77U-MobileSec
"""

from typing import List, Dict


async def interactive_mode(orchestrator):
    """Run in interactive mode for APK selection with configuration options"""
    print("\n🔍 Interactive APK Analysis Mode")
    print("=" * 50)
    
    # Ask for debug mode
    debug_choice = input("Enable debug mode for verbose output? [y/N]: ").strip().lower()
    debug_mode = debug_choice in ['y', 'yes']
    
    if debug_mode != orchestrator.debug:
        orchestrator.debug = debug_mode
        orchestrator.detector.debug = debug_mode
        print(f"🐛 Debug mode: {'Enabled' if debug_mode else 'Disabled'}")
    
    # Ask for LLM choice
    print("\n🤖 Choose AI Analysis Method:")
    print("1. 🏠 Local Ollama (DeepSeek Coder-6.7B) [default]")
    print("2. 🌐 GROQ API (requires API key)")
    
    while True:
        llm_choice = input("Enter your choice (1-2) [default: 1]: ").strip()
        
        if llm_choice == '' or llm_choice == '1':
            llm_preference = 'ollama'
            break
        elif llm_choice == '2':
            llm_preference = 'groq'
            break
        else:
            print("❌ Invalid choice. Please enter 1 or 2.")
    
    # Update LLM preference
    if llm_preference != orchestrator.llm_preference:
        orchestrator.llm_preference = llm_preference
        orchestrator.use_local_llm = (llm_preference == 'ollama')
        orchestrator.detector.use_local_llm = orchestrator.use_local_llm
        llm_name = "Ollama (DeepSeek Coder-6.7B)" if llm_preference == 'ollama' else "GROQ API"
        print(f"🤖 LLM preference: {llm_name}")
    
    # Ask for vulnerability auto-fix option
    print("\n🔧 Vulnerability Auto-Fix:")
    fix_choice = input("Enable vulnerability auto-fix prompt after analysis? [y/N]: ").strip().lower()
    fix_vulnerabilities = fix_choice in ['y', 'yes']
    print(f"🔧 Auto-fix mode: {'Enabled' if fix_vulnerabilities else 'Disabled'}")
    
    # Ask for dynamic analysis option
    print("\n🚀 Dynamic Analysis (MobSF):")
    dynamic_choice = input("Enable dynamic analysis using MobSF API? [y/N]: ").strip().lower()
    run_dynamic_analysis = dynamic_choice in ['y', 'yes']
    print(f"🚀 Dynamic analysis: {'Enabled' if run_dynamic_analysis else 'Disabled'}")
    
    if run_dynamic_analysis:
        print("ℹ️  Note: MobSF server must be running. You'll be prompted for API key during analysis.")
    
    # Ask for analysis type (optional)
    print("\n📱 APK Analysis Type:")
    print("1. 🔍 Auto-detect framework type [default]")
    print("2. ☕ Force Java/Kotlin analysis")
    print("3. ⚛️  Force React Native analysis")
    print("4. 🦋 Force Flutter analysis")
    
    force_type = None
    while True:
        type_choice = input("Enter your choice (1-4) [default: 1]: ").strip()
        
        if type_choice == '' or type_choice == '1':
            force_type = None
            break
        elif type_choice == '2':
            force_type = 'java'
            break
        elif type_choice == '3':
            force_type = 'react-native'
            break
        elif type_choice == '4':
            force_type = 'flutter'
            break
        else:
            print("❌ Invalid choice. Please enter 1-4.")
    
    if force_type:
        print(f"🎯 Analysis type: Forced to {force_type}")
    else:
        print("🔍 Analysis type: Auto-detect")
    
    # Main analysis loop
    while True:
        print("\n" + "="*50)
        print("Interactive Menu Options:")
        print("  1. Analyze APK file")
        print("  2. List available sample APKs")
        print("  3. Show version information")
        print("  4. Run system doctor")
        if orchestrator.debug:
            print("  5. Debug: Test APK type detection")
            print("  6. Debug: Show analyzer status")
        print("  0. Exit")
        
        max_choice = 6 if orchestrator.debug else 4
        choice = input(f"\nEnter your choice (0-{max_choice}): ").strip()
        
        if choice == '1':
            apk_path = input("\n📁 Enter APK file path: ").strip().strip('"\'')
            if apk_path:
                if orchestrator.debug:
                    print(f"🐛 DEBUG: Starting analysis with settings:")
                    print(f"🐛 DEBUG: - APK path: {apk_path}")
                    print(f"🐛 DEBUG: - LLM: {orchestrator.llm_preference}")
                    print(f"🐛 DEBUG: - Force type: {force_type or 'auto-detect'}")
                    print(f"🐛 DEBUG: - Debug mode: {orchestrator.debug}")
                    print(f"🐛 DEBUG: - Auto-fix: {fix_vulnerabilities}")
                    print(f"🐛 DEBUG: - Dynamic analysis: {run_dynamic_analysis}")
                
                await orchestrator.detect_and_analyze(
                    apk_path, 
                    force_type, 
                    fix_vulnerabilities=fix_vulnerabilities,
                    run_dynamic_analysis=run_dynamic_analysis
                )
            else:
                print("❌ Please provide a valid APK path")
        
        elif choice == '2':
            # List sample APKs
            from ..cli.commands import list_sample_apks
            list_sample_apks()
        
        elif choice == '3':
            # Show version
            from ..cli.interface import display_banner
            display_banner()
        
        elif choice == '4':
            # Run system doctor
            from ..system.doctor.main_doctor import MobileSecDoctor
            doctor = MobileSecDoctor(detailed=orchestrator.debug)
            doctor.run_doctor()
        
        elif choice == '0':
            print("👋 Goodbye!")
            break
        
        elif choice == '5' and orchestrator.debug:
            apk_path = input("Enter APK file path for detection test: ").strip().strip('"\'')
            if apk_path:
                orchestrator.debug_test_detection(apk_path)
                
        elif choice == '6' and orchestrator.debug:
            orchestrator.debug_show_status()
        
        else:
            print(f"❌ Invalid choice. Please enter a number between 0 and {max_choice}.")


def ask_for_fix_option(vulnerabilities):
    """Ask user which vulnerabilities they want to fix"""
    if not vulnerabilities:
        return []
    
    print("\n🔧 Would you like to fix any of these vulnerabilities?")
    print("Options:")
    print("  • Enter numbers separated by commas (e.g., 1,3,5)")
    print("  • Enter 'all' to fix all vulnerabilities")
    print("  • Enter 'none' or 'skip' to skip fixing")
    
    while True:
        choice = input("\nEnter your choice: ").strip().lower()
        
        if choice in ['none', 'skip', 'n']:
            return []
        elif choice == 'all':
            return list(range(1, len(vulnerabilities) + 1))
        else:
            try:
                # Parse comma-separated numbers
                indices = [int(x.strip()) for x in choice.split(',') if x.strip().isdigit()]
                # Validate indices
                valid_indices = [i for i in indices if 1 <= i <= len(vulnerabilities)]
                if valid_indices:
                    return valid_indices
                else:
                    print(f"❌ Invalid selection. Please enter numbers between 1 and {len(vulnerabilities)}")
            except ValueError:
                print("❌ Invalid input. Please enter numbers separated by commas.")
