"""AI-provider configuration checker for lu77U-MobileSec."""

from ..config import user_settings, credentials
from ..ui.colors import Colors
from ..utils.verbose import verbose_print

def check_ai_provider_configured(verbose: bool = False) -> bool:
    """True if the active provider has what it needs to attempt a run."""
    name = user_settings.get_active_provider()
    cfg = user_settings.get_provider_config(name)
    verbose_print(f"Active AI provider: {name}", verbose)

    if name == "ollama":
        if cfg.get("mode") == "local":
            return True  # local lifecycle (Phase 2) handles server + model selection
        configured = credentials.has_api_key("ollama")
    elif name == "custom":
        configured = bool(cfg.get("base_url"))
    else:  # claude / openai / gemini
        configured = credentials.has_api_key(name)

    verbose_print(f"  Configured: {configured}", verbose)
    return configured

# Backward-compatible alias (older callers import this name).
def check_ollama_configured(verbose: bool = False) -> bool:
    return check_ai_provider_configured(verbose=verbose)

def get_ollama_setup_message(verbose: bool = False) -> str:
    name = user_settings.get_active_provider()
    message = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  AI Provider Configuration Required
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The active AI provider ("{name}") is not fully configured.

To perform vulnerability analysis:
  1. Open option 4. Edit Settings from the main menu
  2. Choose the provider you want and set its API key
     (or, for Custom, its base URL/IP and key)
  3. Optionally switch the active provider or pick a model

Note: Analysis cannot proceed until the active provider is configured.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
    verbose_print(message, verbose)
    return message

def validate_ollama_before_analysis(require_confirmation: bool = True) -> bool:
    if not check_ai_provider_configured(verbose=False):
        print(get_ollama_setup_message())
        if require_confirmation:
            print(f"\n{Colors.INFO}Press Enter to return to main menu...{Colors.RESET}")
            input()
        return False
    return True