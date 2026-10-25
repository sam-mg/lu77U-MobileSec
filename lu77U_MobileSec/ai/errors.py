#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.ai.errors

Purpose:
    Classify a provider failure into one of four kinds, so the caller can decide whether to retry, back off, rotate to the next API key, or stop.

Responsibilities:
    Define ErrorClass, extract a status code and response body from heterogeneous SDK exceptions, match against phrase tables, and read a Retry-After header.

Dependencies:
    enum only. No provider SDK is loaded here, deliberately.

Implementation notes:
    Every provider raises its own exception type, with its own attribute names and its own wording. Rather than depending on six SDKs and handling each separately, classification works on the stringified exception plus whatever status code can be found by duck typing. That keeps this module importable with no SDK installed and means a new provider needs no change here. Phrase matching is the primary signal and status codes are secondary, because the distinction that matters most -- an exhausted quota versus a temporary rate limit -- is not visible in the status code. Both commonly arrive as 429, and retrying an exhausted quota wastes the entire retry budget on requests that cannot succeed.

Known limitations:
    Phrase tables are inherently brittle: a provider rewording its error message silently downgrades a fatal condition to transient, and the tool then retries something hopeless. The tables are checked against real provider messages and must be updated when a provider changes its wording.

Security considerations:
    Response bodies are read for classification and truncated. Provider errors sometimes echo request content, so a classified message must not be logged raw without passing through the verbose module's redaction.
"""

from enum import Enum
from typing import Optional


class ErrorClass(Enum):
    """
    Purpose:
        The four outcomes a provider failure can have, distinguished by what the caller should do next.

    Attributes:
        TRANSIENT: Unclassified failure. Retry with backoff.
        THROTTLED: Rate limited. Retry after a delay, honouring Retry-After when present.
        FATAL_QUOTA: Credit or usage allowance exhausted. Retrying cannot help; rotate to another key or stop.
        FATAL_AUTH: Credential rejected, missing, or the CLI is not logged in. Retrying cannot help.

    Invariants:
        Exactly one class per failure, chosen by the fixed precedence in classify.

    Thread-safety:
        An enum, so immutable and safe to share.
    """
    TRANSIENT = "transient"
    THROTTLED = "throttled"
    FATAL_QUOTA = "fatal_quota"
    FATAL_AUTH = "fatal_auth"


_QUOTA_PHRASES = (
    "session usage limit", "usage limit", "upgrade for higher limits",
    "insufficient_quota", "quota exceeded", "exceeded your current quota",
    "credit balance is too low", "billing", "monthly limit", "out of credits",
    "payment required",
    "usage limit reached", "limit will reset", "weekly limit",
    "rate_limit_exceeded", "you've hit your usage limit",
    "exceeded your premium request", "resets at",
)

_AUTH_PHRASES = (
    "invalid api key", "incorrect api key", "invalid_api_key",
    "authentication_error", "authentication failed", "unauthorized",
    "permission_denied", "no api key",
    "not authenticated", "not logged in", "please sign in",
    "run `claude login`", "run `codex login`", "invalid_grant",
    "is not installed or not on path",
)

_THROTTLE_PHRASES = ("rate limit", "ratelimit", "too many requests")


def _status_of(exc) -> int:
    """
    Purpose:
        Recover an HTTP status code from an exception raised by any provider SDK.

    Parameters:
        exc: The exception, or any object.

    Returns:
        The status code, or 0 when none could be found.

    Implementation notes:
        Attribute names are tried in order -- status_code, status, code -- then the nested response object, because the SDKs disagree on all of them. Each candidate is type-checked as an int, since some SDKs expose a string code or an error-name enum under the same attribute. Returning 0 rather than None lets callers compare against status numbers without a None guard; no real status is 0.
    """
    for attr in ("status_code", "status", "code"):
        value = getattr(exc, attr, None)
        if isinstance(value, int):
            return value
    response = getattr(exc, "response", None)
    if response is not None:
        value = getattr(response, "status_code", None)
        if isinstance(value, int):
            return value
    return 0


def _body_of(exc) -> str:
    """
    Purpose:
        Recover the response body text from an exception, where the useful wording often lives.

    Parameters:
        exc: The exception, or any object.

    Returns:
        At most 2000 characters of body text, or an empty string when unavailable.

    Implementation notes:
        Truncated because an error body can carry a full HTML error page, and the phrases being matched appear near the start. Bounding it also bounds the cost of classifying a pathological response. Guarded broadly because reading .text on a streamed or already-consumed response can raise, and a failure to classify must never replace the original error.

    Security considerations:
        Bodies can echo parts of the request, which includes decompiled source. Treat the result as sensitive.
    """
    response = getattr(exc, "response", None)
    if response is None:
        return ""
    try:
        return str(getattr(response, "text", "") or "")[:2000]
    except Exception:
        return ""


def classify(exc_or_message) -> ErrorClass:
    """
    Purpose:
        Decide what kind of failure a provider error represents.

    Parameters:
        exc_or_message: An exception or a message string.

    Returns:
        The matching ErrorClass. TRANSIENT when nothing matched, so an unrecognised failure is retried rather than treated as fatal.

    Complexity:
        O(n * p) for message length n and the total phrase count p.

    Implementation notes:
        Precedence is quota, then auth, then throttling, and it is load-bearing. Quota is checked first because an exhausted allowance frequently arrives as a 429 with rate-limit-shaped wording; checking throttling first would classify it as retryable and burn the whole retry budget against a wall. Auth is matched on 401 and 403 as well as by phrase, since those codes are unambiguous. The default is TRANSIENT because misclassifying a temporary failure as fatal aborts an expensive analysis, whereas misclassifying a fatal one as transient costs a bounded number of retries.

    Security considerations:
        Matching is done on a lowercased copy of the message and body; nothing is logged here.
    """
    text = (str(exc_or_message) + " " + _body_of(exc_or_message)).lower()
    status = _status_of(exc_or_message)

    if any(phrase in text for phrase in _QUOTA_PHRASES):
        return ErrorClass.FATAL_QUOTA
    if status in (401, 403) or any(phrase in text for phrase in _AUTH_PHRASES):
        return ErrorClass.FATAL_AUTH
    if status == 429 or any(phrase in text for phrase in _THROTTLE_PHRASES):
        return ErrorClass.THROTTLED
    return ErrorClass.TRANSIENT


_UNREACHABLE_PHRASES = (
    "nodename nor servname", "name or service not known", "temporary failure in name resolution",
    "getaddrinfo failed", "network is unreachable", "no route to host", "connection refused",
    "failed to establish a new connection", "cannot connect to host", "failed to resolve",
)


def is_unreachable(exc_or_message) -> bool:
    """
    Purpose:
        Report whether a failure means the provider's host could not be reached at all.

    Parameters:
        exc_or_message: An exception or a message string.

    Returns:
        True for a name-resolution or connection failure: DNS lookup failed, the network is down, or nothing answered.

    Implementation notes:
        These stay TRANSIENT for the retry loop, since a dropped connection often comes back within one call's retries. The distinction matters at scan level: a scan that ends while the host is still unreachable has lost nothing that a later run cannot redo, and is paused for one rather than finished with no findings. A real resumed scan ran while the machine was offline and was recorded as completed with zero findings.
    """
    if isinstance(exc_or_message, (ConnectionRefusedError, ConnectionAbortedError)):
        return True
    text = str(exc_or_message).lower()
    return any(phrase in text for phrase in _UNREACHABLE_PHRASES)


def is_fatal(kind: ErrorClass) -> bool:
    """
    Purpose:
        Report whether a classification means retrying is pointless.

    Parameters:
        kind: The classification.

    Returns:
        True for the quota and auth classes.

    Implementation notes:
        Exists so that callers test intent rather than enumerating enum members, which keeps the retry logic correct when a new fatal class is added.
    """
    return kind in (ErrorClass.FATAL_QUOTA, ErrorClass.FATAL_AUTH)


def retry_after_for(exc) -> Optional[float]:
    """
    Purpose:
        Read the provider's own Retry-After hint from a throttling response.

    Parameters:
        exc: The exception carrying the response.

    Returns:
        The delay in seconds, or None when the header is absent or unusable.

    Implementation notes:
        Both header spellings are tried, since header mappings are not always case-insensitive once they have passed through an SDK. Negative values are clamped to zero. Only the seconds form is parsed; the HTTP-date form yields None, which sends the caller to its own backoff -- acceptable, since providers overwhelmingly send the numeric form. Honouring the server's hint matters: backing off less than asked invites a longer ban, and backing off far more wastes wall-clock time in an already slow analysis.
    """
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", None) if response is not None else None
    if not headers:
        return None
    value = headers.get("Retry-After") or headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return None
