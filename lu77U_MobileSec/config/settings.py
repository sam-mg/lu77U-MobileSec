#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.config.settings

Purpose:
    Default values for every runtime knob, in one readable place: which model to use, how long to wait, how many times to retry, whether optional subsystems are on.

Responsibilities:
    Re-export the packaging identity under APP_* names and declare the tunable defaults.

Dependencies:
    .._metadata only.

Implementation notes:
    These are defaults, not live configuration. Values a user can change are read at runtime through user_settings and credentials; the names here are the fallbacks used when nothing has been configured. The timeouts are generous on purpose. A request timeout of 600 seconds and a keep-alive of 30 minutes suit a local model loading several gigabytes of weights, where a conventional API timeout would abort a request that was progressing normally. num_predict is large for the same reason: a full vulnerability report in JSON is long, and a low cap truncates findings mid-response. OLLAMA_THINKING_ALLOWANCE is added to any smaller cap a caller sets, because thinking is always on and its trace counts against num_predict; 4,096 covers the trace of nine in ten review, triage and device-step calls measured across a week of scans. AI_MODEL_OLLAMA_ID stays empty because user_settings seeds a brand-new settings file from it: any value here overrides the registry default on every fresh install, which is how a retired model kept reaching first scans after the registry default had been fixed.

Security considerations:
    OLLAMA_API_KEY is an empty placeholder and must stay empty. Real keys live in the OS keychain via .credentials; committing one here would publish it to every checkout of this repository.
"""

from .._metadata import AUTHOR, DESCRIPTION, EMAIL, HOMEPAGE, NAME, VERSION

APP_NAME = NAME
APP_VERSION = VERSION
APP_DESCRIPTION = DESCRIPTION
APP_AUTHOR = AUTHOR
APP_EMAIL = EMAIL

ANDROGUARD_LOGGING = True
PDF_GENERATION = True

OLLAMA_API_KEY = ""
OLLAMA_API_HOST = "https://api.ollama.com"
AI_MODEL_OLLAMA_ID = ""
OLLAMA_MAX_RETRIES = 3

OLLAMA_KEEP_ALIVE = "30m"
OLLAMA_RETRY_DELAY = 2
OLLAMA_REQUEST_TIMEOUT = 600

OLLAMA_NUM_PREDICT = 16384
OLLAMA_MAX_NUM_PREDICT = 65536
OLLAMA_THINKING_ALLOWANCE = 4096

JADX_PATH = ""

SOCIAL_LINKS = {
    "GitHub Repository": HOMEPAGE,
}
