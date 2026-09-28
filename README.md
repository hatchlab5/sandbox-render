# sandbox-render

Render untrusted HTML — from a language model, a plugin, a user-submitted template —
without letting it fetch, load, or submit anything. One file, no dependencies.

```html
<script src="sandbox-render.js"></script>
<script>
  const frame = SandboxRender.frameFor(modelOutput, "chart");
  document.querySelector("#pane").appendChild(frame);
</script>
```

The fragment is assumed to be **fully attacker-controlled**. In the LLM case that is the
normal situation and not the edge case: a stranger types into a prompt and the output
lands in your DOM.

---

## The idea: contain where it lands, not what it says

The tempting approach is to restrict the *content* — an allow-list of tags, a sanitizer, a
narrow rendering vocabulary. That works right up until the feature is "let it build
something custom", because a vocabulary narrow enough to be provably safe cannot express
"anything".

So the boundary goes around the **output surface** instead. Inside the frame the content
is completely free, because the frame cannot fetch, load, or submit.

Two controls do that, and they answer two different questions.

### 1. The sandbox attribute — one entry long

```js
sandbox = "allow-scripts"
```

That is a short enumerable allow-list over a default-deny, which means it is provable by
**inspection** rather than by spot-check. Read the list; the default denies everything
absent from it.

> **Never add `allow-same-origin` alongside `allow-scripts`.** The two together defeat the
> sandbox entirely — a frame granted both runs at its real origin and can **remove its own
> sandbox attribute**.

That pair is legitimate elsewhere. If you are guarding navigation and popups for markup
*you* authored, `allow-scripts allow-same-origin` is a reasonable thing to write, and you
will find it in real codebases doing exactly that correctly. **Which is precisely why it
will look right to the next reader here too.** It is correct for that threat model and
wrong the instant the content is machine-generated.

### 2. A CSP inside the srcdoc — because the frame runs on someone else's machine

"Egress" names two different controls and only one of them is server-side. Your firewall
governs your hosts. **A sandboxed frame runs on the visitor's machine**, where no firewall
of yours is anywhere near it. It has nothing of yours to exfiltrate — but it can *beacon
outward*, and it can pull third-party content in.

The only control that reaches it is a restrictive CSP carried inside the srcdoc:

```
default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline';
img-src 'none'; form-action 'none'; base-uri 'none'
```

Three things about that string are deliberate and easy to get wrong:

- **`connect-src` is absent on purpose.** It falls back to `default-src 'none'`, which
  denies fetch, XHR, WebSocket and `sendBeacon` together. Adding a `connect-src` line
  would *override* that deny, not reinforce it.
- **`form-action` and `base-uri` must be stated.** Neither is covered by `default-src`.
  Without `form-action 'none'` the content can render a sign-in form and **submit it
  somewhere**; without `base-uri 'none'` a `<base>` tag re-points every relative URL.
- **`'unsafe-inline'` is not a weakening here.** Inline *is* the content, and the frame is
  an opaque origin that cannot fetch, load, or submit.

And one that is a trap: **a CSP delivered in a `<meta>` tag silently ignores
`frame-ancestors`, `report-uri` and `sandbox`.** Putting them there looks like defence and
binds nothing. The sandbox *attribute* on the parent element is what carries that weight.

---

## Measured, not asserted

`test/containment-proof.py` mounts deliberately hostile content in a real headless Chromium
and measures what actually leaves the browser — `fetch`, an `<img>`, `sendBeacon`, a
WebSocket, an auto-submitting form POST, and an attempt to read the parent document.

```
=== PROTECTED (SandboxRender.frameFor) ===
  requests the naive counter would see : 1
  actually LEFT the browser            : 0
  blocked before the network           : 1
     contained  img      <- csp
  read parent document                 : THREW

=== CONTROL (no sandbox, no CSP — same body) ===
  actually LEFT the browser            : 3
     ESCAPED    form     <- net::ERR_NAME_NOT_RESOLVED
     ESCAPED    img      <- net::ERR_NAME_NOT_RESOLVED
     ESCAPED    fetch    <- net::ERR_NAME_NOT_RESOLVED
```

Look at the first two lines of the protected run, because that gap is the whole point.

**A CSP-blocked resource still fires a request event.** So counting requests conflates
*blocked* with *left the browser*, and a naive check reports a leak that is not there — or
reports containment because it counted the wrong thing. What separates them is the failure
**reason**: `csp` means it was stopped before the network; `ERR_NAME_NOT_RESOLVED` against
a host that cannot resolve means it genuinely left this process and hit DNS. Every probe
targets an unresolvable host so those are the only two outcomes available.

**The control arm exists for the same reason.** A probe reporting "0 escapes" proves
nothing unless the same probe reports escapes for an unprotected frame. It does — three of
them. If the control ever stops leaking, the instrument is broken and the result is void,
and the script exits non-zero to say so.

*(One honest limit: in the control run the form POST navigates the frame away, so the
parent-read probe there is inconclusive. The protected run's `THREW` is definitive — an
opaque origin cannot reach the parent document.)*

---

## What this does not cover

**Pixels.** Containment is perfect and irrelevant against a convincing fake sign-in form.
The frame renders one, it sits inside a page the visitor already trusts, and they type
their password into attacker HTML. `form-action 'none'` stops the submit — but a script can
still read the field, and the visitor has still typed their password into a box.

> The real control for that is **structural**: credential entry must never happen inside a
> sandboxed pane. Sign-in belongs to your trusted chrome, and the code that mounts it
> should *refuse* to mount into one of these hosts. A paragraph in a design note is not a
> control.

`looksLikeCredentialPrompt(body)` is shipped as a **weak net, named as weak**. It returns a
*reason* rather than a boolean, because a refusal that cannot say why teaches the next
reader nothing:

```js
SandboxRender.looksLikeCredentialPrompt('<input type="password">')  // "a password input"
SandboxRender.looksLikeCredentialPrompt('<p>hello</p>')             // null
```

Its limit is asserted in the test suite rather than only described: content can build a
password field at runtime with one line of script, `allow-scripts` is on by design, and the
filter does not catch it. **A weak net named as weak is fine; a weak net mistaken for the
control is how a boundary quietly stops existing.**

**Navigation.** A contained frame can still navigate *itself* — `window.location = …`, a
`<meta http-equiv="refresh">`, or an `<a>` click — and that self-navigation is an outbound
GET that no CSP directive blocks. `default-src 'none'` governs sub-resource *loads*, not the
document changing its own location, so a data-bearing beacon smuggled into a URL is **not
fully prevented**. What is prevented: `allow-top-navigation` is absent, so it cannot
navigate *your* top page — only its own throwaway frame. But that GET still leaves the
browser, so the network-level claim is "cannot fetch, load, or submit," not "emits nothing."

**Resource exhaustion** is accepted, not solved. Contained content can spin the CPU —
annoying, visible, recoverable, bounded by the tab. Named so it is not a surprise.

**Redaction is not containment.** Scanning a body for things that look sensitive catches
only the forms somebody thought of. Useful reduction; not an isolation claim.

---

## Two smaller decisions worth stealing

**`srcdoc`, never `src`.** The content never becomes a fetchable URL on your origin, so it
cannot be linked, indexed, or re-requested out of context.

**No `loading="lazy"`.** It makes the frame's execution conditional on layout, which turns
every containment assertion about the frame's *behaviour* into a coin toss: an off-screen
frame never runs, so "no beacon was sent" and "the frame never started" produce an
identical trace — and the second one reads as a pass. **A security check that goes green
because the subject never woke up is worse than no check at all.**

## API

- `frameFor(body, label?, opts?)` — a ready-to-append `<iframe>`. `body === null` renders a
  visible refusal rather than a blank pane, because a silently empty pane is
  indistinguishable from one that was never sent.
- `srcdocFor(body, opts?)` — just the document string, if you manage the element yourself.
  The CSP `<meta>` is always the first thing in `<head>`; a policy that arrives after
  markup has already been parsed does not govern that markup.
- `esc(s)` — minimal `&`/`<`/`>` escaping, ampersand first.
- `SANDBOX`, `CSP`, `REFUSED` — exported as plain strings so your own tests can assert on
  them. The suite here does exactly that.

## Tests

```bash
node --test test/sandbox-render.test.js     # 35 tests, no dependencies

# optional, needs playwright + chromium:
python3 test/containment-proof.py           # exits non-zero if the control stops leaking
```

## License

MIT.
