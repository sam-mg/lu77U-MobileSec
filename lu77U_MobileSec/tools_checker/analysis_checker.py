"""Combined tools checker for APK Analysis"""

from ..ui.colors import Colors
from .jadx_checker import check_jadx_configured, get_jadx_setup_message
from .ollama_checker import check_ollama_configured, get_ollama_setup_message
from ..utils.verbose import verbose_print

def check_analysis_requirements(verbose: bool = False, show_messages: bool = True) -> bool:
    jadx_ok = check_jadx_configured(verbose=verbose)
    ollama_ok = check_ollama_configured(verbose=verbose)
    
    if jadx_ok and ollama_ok:
        verbose_print("All requirements satisfied for APK Analysis", verbose)
        return True
    
    if show_messages:
        print(f"\n{Colors.ERROR}Configuration Required{Colors.RESET}\n")
        
        if not jadx_ok:
            print(f"{Colors.WARNING}JADX is not configured{Colors.RESET}")
        
        if not ollama_ok:
            print(f"{Colors.WARNING}Ollama API Key is not configured{Colors.RESET}")
        
        print(f"\n{Colors.INFO}Please use {Colors.CYAN}4. Edit Settings{Colors.RESET} {Colors.INFO}to configure required tools{Colors.RESET}")
        
        if verbose:
            print()
            if not jadx_ok:
                get_jadx_setup_message(verbose=True)
                print()
            
            if not ollama_ok:
                get_ollama_setup_message(verbose=True)
                print()
        
        print(f"\n{Colors.CYAN}Press Enter to return to main menu...{Colors.RESET}")
        input()
    
    return False

def get_analysis_status() -> dict:
    jadx_ok = check_jadx_configured(verbose=False)
    ollama_ok = check_ollama_configured(verbose=False)
    
    return {
        'jadx_configured': jadx_ok,
        'ollama_configured': ollama_ok,
        'ready_for_analysis': jadx_ok and ollama_ok
    }