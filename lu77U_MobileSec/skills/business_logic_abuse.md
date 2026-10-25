# Business Logic - When the App Trusts Itself

Pattern rules find dangerous calls. They do not find an app that is wrong about
who decides: the client choosing a price, a role or an entitlement that only
the server should. These flaws match no sink and are the ones most often
missed, so look for them on purpose in every app with accounts, payments,
subscriptions, rewards or limits.

## Client-side decisions

The question for every gate: **is the decision made on the server, or in code
an attacker controls?**

- **Entitlement and role flags.** `isPremium`, `isPro`, `hasSubscription`,
  `isAdmin`, `role == "admin"`, `tier`, `plan`, `trialExpired`. Find where each
  is set (a login response, local storage, a constant) and where it is read (the
  screen that shows or hides content). Then check the request that fetches the
  protected content: if it carries only a static API key or a token the free
  user also holds, and nothing the server checks against the user's plan, the
  gate is cosmetic. Flipping the flag - in storage, with a hook, or by patching
  one comparison - unlocks it.
- **Prices and amounts.** A price, discount or total computed in the app and
  sent to the server as authoritative. The finding is the server accepting it,
  which you cannot see; report the client sending it, and say the server must
  recompute.
- **Limits and counters.** "Three free uses", "one redemption", a daily cap
  kept in local storage or memory.
- **Feature flags and kill switches** fetched from a remote config and trusted
  without integrity, or hidden screens (a developer menu behind a tap count)
  that expose keys, environment switches or admin actions.
- **Time.** Trials, OTP windows or licence expiry computed from the device
  clock, which the user sets.

In React Native the gate is usually a ternary in the screen's module
(`isPremium ? <Content/> : <Paywall/>`) fed from AsyncStorage or the login
response; in Flutter it is a boolean field or a SharedPreferences read
compared in the widget's build method; in Java a `SharedPreferences.getBoolean`
or a field checked in `onCreate`. The overview lists entitlement and role flag
names where it can find them - start there.

## Flows worth reading

- **Purchases.** A purchase or subscription verified only on the device (the
  Play Billing `Purchase` object trusted without the server checking it with
  Google), or a receipt/token accepted twice. Look for the code that unlocks
  content after a purchase: does it wait for a server answer?
- **Race conditions.** Redeem, transfer, withdraw or claim flows that check a
  balance or an eligibility and then act in a separate request. A
  check-then-act with no idempotency key can be fired twice in parallel. You
  cannot prove this statically: report it as a lead naming the two requests and
  the test that would prove it (send both at once and see whether both
  succeed).
- **Promo and referral codes** validated locally, or whose single-use status
  lives on the device.
- **Offline mode.** Data edited offline (balances, records, flags) and synced
  back as the truth when the network returns.
- **Sessions.** A token not rotated after login (fixation), sessions on other
  devices not invalidated on logout or password change, a refresh token that
  never expires.
- **Account recovery and device change.** A recovery or device-migration path
  that asks for less than login does - an SMS code alone, a security question,
  a value the app already shows.
- **QR and NFC payloads** that trigger a payment or an action with the
  payload's amount or target and no confirmation.
- **Biometric re-enrolment.** A key or session that should be invalidated when
  a new fingerprint is added (`setInvalidatedByBiometricEnrollment`) but is not.

## Evidence and severity

Most of these are proven by showing the client makes the decision and the
request carries nothing the server could check. Cite: where the flag or value
is set, where it gates, and the request that fetches or performs the protected
thing - with what it sends. That is enough for a finding; whether the server
re-checks is then a one-line test for the owner, which you name.

Severity follows what the bypass gets: paid content for free, another user's
data, money moved. A gate on something cosmetic is a note. A client-side gate
on a payment or an account action is High.
