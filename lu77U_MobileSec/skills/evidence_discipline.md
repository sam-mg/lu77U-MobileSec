# Evidence Discipline - What Your Proof Actually Licenses You to Claim

`finding_quality` decides whether something is worth reporting while you write it.
This is the other half: once you have run something - an `adb` launch, a `frida`
hook, a request to a host - it governs what that observation actually proves, so a
verdict claims exactly what the evidence supports and not one step more. The failure
mode it exists to stop is the quiet upgrade: "the component launches" becoming "the
component is exploitable," "the config allows cleartext" becoming "traffic is
intercepted," "the key is unverified but present" becoming "the key works." Each is a
real observation wearing a bigger claim than it earned.

## The one rule: three facts, never merged

For any issue there are up to three separate facts, and they are not the same fact:

| Fact | What it is | What proves it |
|---|---|---|
| **Configuration** | The app is set up in a way that *permits* the weakness | Reading the manifest / code (`read_source`) |
| **Behaviour** | The app *actually does* the risky thing at runtime | Observing it (`frida` log, `adb` result, captured request) |
| **Impact** | An attacker *gains something named* from it | A demonstrated consumer effect with a negative control |

`usesCleartextTraffic="true"` is configuration. A request going out over HTTP is
behaviour. That request carrying the session token where another app can read it is
impact. Report the level you reached, and name the two you did not as the gap. Never
let a configuration fact stand in the sentence where an impact fact belongs - that is
the single most common way a static tool inflates a report.

## The negative control

A claim of impact needs three things together, and the third is the one usually
missing:

1. **The exact artefact** - this APK build, identified by hash, not "an app like this".
2. **An independently observed consumer effect** - you saw the data come out, the
   action fire, the request succeed. Not "the code path exists".
3. **A negative control** - remove the supposed cause and show the effect disappears.
   If forcing `checkServerTrusted` to pass lets a request through, first show the same
   request *fails* with the hook off. If launching a component leaks data, show the
   leak is absent without your launch. Without the control you have a correlation, not
   a cause, and a reviewer can dismiss the finding by naming any other explanation.

An observation you cannot pair with a negative control is still worth a `note` - write
it as "observed, cause not isolated," not as a proven vulnerability.

## Runtime launchability is not reachability

`adb am start -n <pkg>/<component>` running the component proves **shell-identity
launchability**: that *you*, with adb, could start it. It does not prove that another
app with no permission could, and it is that second actor the finding is about. adb
runs with shell privileges an attacker app does not have. Promote an exported-component
finding only after a caller that models the real attacker - a crafted Intent from an
unprivileged context, `content query` against an exported provider, a broadcast with no
held permission - reaches a **named sensitive effect**, and only with the negative
control above. Before any launch, confirm the installed build's hash matches the APK you
analysed; a launch against a different build is evidence about the wrong app.

## Forcing a value proves the check, not the protection

When a `frida` hook forces a return - root check to `false`, biometric callback to
success, a client-side `isPremium` flag to `true` - what you have proven is that **the
check is client-side and defeatable**. That is the finding, and it is a real one. What
you have *not* proven is that whatever sat behind the check was otherwise protected: if
the "premium" content was never fetched from a server that re-checks entitlement, you
bypassed a gate that was already cosmetic. State what the bypass actually buys - a
server round-trip skipped, a local-only guard removed - not merely that the hook
returned what you told it to. `offensive_android` and `objection_runtime_toolkit` cover
the mechanics; this covers the claim you attach to them.

## Touching a host is a scoped, labelled act

A URL recovered from decompiled code is untrusted input, not an authorised target. Do
not send a request to a host just because the app names it - the host may belong to a
third party, and the URL may be dead, internal, or intentionally public. Only probe a
host the engagement explicitly authorises, and when you do:

- Strip query strings and token-like path segments out of the evidence you keep; a
  saved URL should not become the place a secret leaks to.
- A credential-free `2xx` means **"responded without credentials"**, not
  "authorization is broken". It says nothing about intended access policy or object
  ownership - the resource may be public by design. An authorization finding needs the
  owner's intent and a negative control (the same request *denied* in a state that
  should deny it), not one anonymous success.

## Candidates, identifiers, and advisories all carry a state

Three kinds of automated signal are routinely over-read; keep each one's state honest:

- **Secret candidate**: "verified" means a provider confirmed the credential is live at
  check time - it does **not** establish what that credential can do or that the app's
  use of it has impact. "Unverified" may be a false positive. A public identifier (a
  client ID, a project number, a Maps-style key with provider-side restriction) is
  inventory, not a leaked secret, until you show the restriction is missing.
- **Dependency advisory**: an advisory against a shipped version means the app *contains*
  vulnerable code, not that it *reaches* it. Preserve "unavailable" / "unknown" /
  "not queryable" as distinct from "clean" - a lookup that did not run is not a pass.
  Do not invent a severity for a component you could not resolve to a versioned identity.
- **Static match in library/generated code**: still shipped code, so do not dismiss it
  for living under a test/SDK/generated path - but a match there raises the reachability
  bar, not lowers the standard of proof.

## Coverage honesty

Say what you did not reach. A file skipped for size, a DEX that failed to decompile, a
path you never opened - these are part of the result, and hiding them turns "not
examined" into an implied "clean". Two specific traps:

- **A lead is not a call path.** Code in the same class as an entry point, or a name
  that lexically matches, is a reason to look - not evidence the one calls the other.
  Say "same class as the handler," not "called by the handler," unless you traced it.
- **No invented numbers.** Without a labelled corpus of known-vulnerable and known-safe
  apps there is no recall or precision figure to give; "80% covered" is a fabrication.
  "These surfaces were examined, these were not" is the honest shape.

## How it lands in the write-up

Every verdict and every `note` should make the evidence level legible in its own words:

- **Proven**: named effect + negative control + correct build. "The session token is
  read by any installed app: launched a crafted Intent from an unprivileged context,
  captured the token, and confirmed it is absent without the launch."
- **Observed, cause not isolated**: behaviour seen, no negative control yet. "The app
  emits an HTTP request carrying the token; not yet shown that removing the cleartext
  config stops it."
- **Configuration only**: read, not run. "The manifest permits cleartext; no outbound
  HTTP request was observed."

Downgrading to the level you can defend is the honest move, and a reviewer trusts the
proven finding in a report more when the ones beside it are labelled for exactly what
they are.
