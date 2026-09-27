# What Makes a Finding Worth Reporting

Apply this while you write a finding, not after. A report where every real issue
sits under nine pieces of filler is worse than a shorter report, because the
reader stops at the filler and never reaches the real one.

The rule is not "report less". It is **report accurately**. A finding you cannot
fully support still gets reported - at the severity you can support, with the
gap stated. Downgrading is honest; padding and hedging are not.

---

## The thirty-second version

1. **Can an attacker trigger this without owning the device?** Anything needing
   root, ADB, developer mode or physical access to an unlocked phone is not
   something done *to* a victim.
2. **Does the attacker get something you can name?** "Access to data" is not a
   name. "The session token, from any installed app, with no permission" is.
3. **Is it a defect, or an absent hardening control?** Missing pinning, missing
   obfuscation and missing root detection are controls. Their absence is worth
   saying once, together, at Informational.

Any "no" means it is a note. Write it as one and move on.

---

## Before you commit a finding

**Is the code reachable?** Find a caller. A perfect SQL injection in a method
nothing invokes is a code-quality note. Trace back to an entry point - an
exported component, a deep link, a network response, WebView content - or say
that you could not.

**Does it run in the release build?** `BuildConfig.DEBUG` guards are everywhere
in decompiled code and are easy to read past. Check the guard.

**Is it the platform working as designed?** Implicit intent resolution, `adb
backup` copying app data, WebViews loading HTTP on an old target - all
documented behaviour. The finding has to show impact beyond it.

**Have you named the thing?** Every class in `vulnerability_classes` says what
it needs. Exported component: the action or data a caller gets. Hardcoded
secret: the service and the access. Weak crypto: what it protects. Insecure
storage: which value, and how it leaves the device.

**Is this the same issue twice?** One misconfigured WebView described from two
files is one finding. Merge it.

**Would the fix be actionable?** "Validate input" is not a fix. "Compare
`uri.getHost()` against an exact allowlist and reject every scheme but https"
is. If you cannot write the concrete change, you have not understood the finding
well enough to report it.

---

## Severity

Severity comes from the CVSS vector, and the vector comes from what the code
does - not from how bad the class sounds.

The most common error is `AV:N` on a local attack. An exported component is
reached by another app *on the device*: that is `AV:L`. A deep link a victim must
tap is `AV:N` but `UI:R`. Scope changes (`S:C`) when exploiting the flaw affects
something beyond the vulnerable component's own authority - a WebView bridge
reaching native code is the standard example.

A finding with no demonstrated impact scores low across C/I/A, and a low CVSS
score is a correct outcome, not a failure.

---

## Credentials

Never send a request using a credential you found, to any service, to check
whether it is live. The account belongs to the app's owner, not to you, and an
unauthorised request against their infrastructure is not evidence - it is an
incident.

Document it statically instead: where it is, what service and key type it
belongs to, what that key type grants according to the provider's own
documentation, and a request that the owner confirm it server side. That is a
complete finding. A finding is never weakened for declining to probe.

---

## What good looks like

State, in order: what the flaw is, where it is (file, method, component), the
attacker's steps from entry point to impact, the reproduction command, and the
concrete fix.

If you cannot write the attacker's steps, you do not have a finding yet - you
have a lead. Report it as one, at Informational, and say what you would need to
read to settle it. That is genuinely useful to the person maintaining the app,
and far more useful than the same lead dressed up as a High.
