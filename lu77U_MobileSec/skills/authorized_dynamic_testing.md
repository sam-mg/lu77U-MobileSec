# Authorized Dynamic Testing - Operating Safely on a Live App

The static phase reads an APK, which is inert. The dynamic phase installs it, launches
it, hooks it, and sometimes talks to its backend - actions that change a running system
and that only some engagements permit. This skill governs *how you operate* once you
leave static reading, so the runtime work stays inside what the engagement authorised
and leaves the device and the backend as you found them. It sits beside
`offensive_android` (how to prove a finding at runtime) and `evidence_discipline` (what
a runtime observation is allowed to claim); this is the third leg - what you are allowed
to *do* to get there.

## The authorization gate

Static analysis of an APK the user handed you needs no further permission - it is their
file. The moment an action reaches outside that file, it needs authorization, and the
line is worth naming precisely:

| Action | Needs explicit authorization? |
|---|---|
| Decompile, read source, parse the manifest (`read_source`, `search_code`) | No - the APK is the user's own artefact |
| Install and launch the app on a device/emulator the user controls | The user's device: implied by handing you the app. A device that is not theirs: yes |
| `frida` hooks, `run-as` reads, component launches on that device | Same as above - the user's own device is implied, anything else is not |
| Any request to a backend host the app names | **Yes, always** - the host is almost never the user's to test (see below) |
| Repackaging, patching, or re-signing the APK | Note it, and only when a runtime hook cannot get the same evidence |

If the target app or device is not clearly the user's to test, say so and stay in
advisory mode: analyse what they give you, do not reach out and touch anything.

## The backend is a separate target

A URL recovered from the app is not in scope because the app names it. The server
belongs to whoever runs it - often a third party (an SDK's telemetry endpoint, a CDN, a
payment provider), and testing it is a distinct authorization from testing the app.
`evidence_discipline` covers how to *read* an anonymous response; the rule *here* is
earlier: do not send the request at all unless the engagement explicitly authorises that
host. When in doubt, extract the endpoint as an inventory item and hand it back as "a
host to confirm in scope," not a target you probed.

## Least-intrusive first

Reach for the quietest action that produces the evidence, and escalate only when it does
not:

1. **Read before you run.** If `read_source` already shows the trust-all `TrustManager`,
   you may not need to hook anything to substantiate the finding.
2. **Observe before you change.** A `frida` hook that logs a value and calls through
   (`frida_hook_recipes`) leaves behaviour intact. Forcing a return value changes what
   the app does - do it only when the finding is that the check is defeatable.
3. **Target before you sweep.** Hook the one class the finding named before reaching for
   a process-wide `frida-trace`; the narrow hook is quieter, cheaper, and cleaner
   evidence.
4. **Hook before you patch.** A runtime bypass proves the same point as repackaging the
   APK with the check removed, without producing a modified artefact you then have to
   account for. Prefer it.

## Tag what each runtime step does to the app

Before a dynamic step, know which of three levels it sits at, and record it so the report
is honest about what was done:

- **Passive** - reading the sandbox with `run-as`, attaching a logging hook, capturing
  `logcat`. Observes without altering behaviour.
- **Behaviour-changing** - disabling SSL pinning, forcing a root/biometric check,
  launching an exported component, flipping a client-side flag. The app now does
  something it would not have; the evidence is real but the run is no longer a clean
  observation of normal operation.
- **Modifying** - repackaging, patching smali, re-signing, installing a persistent
  hook, or anything that leaves the device or the APK changed after the session.

Passive and behaviour-changing steps are the normal tools of the job. A modifying step
needs a reason a lighter step could not serve, and it needs cleanup (below).

## Leave no residue

Runtime work is reversible by default:

- Uninstall test builds and remove pushed files (`adb push`ed certificates, scripts)
  when the session ends.
- Never modify backend data as a test - a mutating request against a real service
  (placing an order, transferring a balance, deleting a record) is out of bounds even
  when the app is in scope. Prove the flaw reaches the mutation; do not perform it.
- Do not leave a persistent hook, a disabled protection, or a rooting artefact behind on
  a device that is not a disposable test device.

## Preserve the evidence, pinned to the exact build

Every runtime observation is evidence, and evidence needs provenance:

- Record the exact build you tested - its package name and APK hash - so a finding is
  anchored to one artefact and cannot be waved off as "a different version"
  (`evidence_discipline` makes the same point for its build-hash rule).
- Keep the raw output - the hook's `send()` log, the `adb` result, the captured request -
  alongside your reading of it, timestamped, rather than only your paraphrase.
- Redact secrets out of what you keep: a captured token belongs in the finding as "the
  session token, value withheld," not pasted in full into saved output.

## Hard limits

Some actions are out of bounds no matter what the engagement claims to authorise, because
this is a security-assessment tool and these are not assessment:

- **Denial of service** against the app's backend - no volumetric floods, no
  resource-exhaustion "tests" of a live service.
- **Mutating a real backend for gain** - bypassing a payment or entitlement check is a
  finding to *demonstrate reaches the server*, never a transaction to actually perform.
- **Touching safety-critical systems** - an app controlling a medical, vehicle, or
  industrial-safety function is not something to instrument without a safety review in
  the engagement.
- **Persisting beyond the engagement** - no backdoor, no retained implant, on any device
  that outlives the test.

If a request maps to one of these, decline the action and offer the assessment-safe
version that still proves the point - demonstrate the reachable path, stop at the edge of
the harm.
