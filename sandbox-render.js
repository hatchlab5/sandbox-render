/* sandbox-render.js — render untrusted HTML safely, in one dependency-free file.
 *
 *   window.SandboxRender = { SANDBOX, CSP, REFUSED, srcdocFor, frameFor, esc,
 *                            looksLikeCredentialPrompt }
 *
 * The case this is built for: something you do not control authored a fragment of HTML --
 * a language model, a plugin, a user-submitted template -- and you want to put it on the
 * page. Assume the fragment is fully attacker-controlled, because in the LLM case that is
 * the normal situation rather than the edge case: a stranger types into a prompt and the
 * output lands in your DOM.
 *
 * The approach: do not try to restrict WHAT the content may say. Restrict WHERE IT LANDS.
 * A vocabulary narrow enough to be provably safe cannot express "anything custom", so the
 * boundary goes around the output surface instead. Inside the frame the content is free,
 * because the frame cannot fetch, load, or submit.
 *
 * == THE SANDBOX LIST IS THE WHOLE CONTROL, AND IT IS ONE ENTRY LONG ==================
 * `sandbox="allow-scripts"`, nothing else. That is a short enumerable allow-list over a
 * default-deny, so it is provable by INSPECTION rather than by spot-check. Read the list;
 * the default denies everything absent from it.
 *
 * NEVER ADD `allow-same-origin` ALONGSIDE `allow-scripts`. The two together defeat the
 * sandbox entirely: a frame granted both runs at its real origin and can REMOVE ITS OWN
 * SANDBOX ATTRIBUTE. The pair is legitimate in other contexts -- if you are guarding
 * navigation and popups for content you authored yourself, it is correct -- and that is
 * exactly why it will look right to the next reader here too. It is wrong the instant the
 * content is machine-generated.
 *
 * == CSP INSIDE THE srcdoc — THE SECOND, SEPARATE EGRESS QUESTION =====================
 * "Egress" names two different controls and only one of them is server-side. A sandboxed
 * frame with `allow-scripts` still runs on the VISITOR'S machine, where no firewall of
 * yours is anywhere near it. It has nothing of yours to exfiltrate, but it can BEACON
 * outward and pull third-party content in. The only control that reaches it is a
 * restrictive CSP carried inside the srcdoc itself.
 *
 * Two entries are NOT covered by `default-src` and so must be stated explicitly. That is
 * the whole reason the policy string is not shorter:
 *   - `form-action 'none'` — a form POST is not governed by default-src. Without it, the
 *     content could render a sign-in form and SUBMIT IT SOMEWHERE. This is the one entry
 *     that speaks to phishing rather than to beaconing.
 *   - `base-uri 'none'`    — a <base> tag would otherwise re-point every relative URL.
 * `connect-src` is deliberately ABSENT so it falls back to `default-src 'none'`: fetch,
 * XHR, WebSocket and sendBeacon are all denied by the default.
 *
 * `'unsafe-inline'` for script and style is intentional and is not a weakening. Inline IS
 * the content; the frame is an opaque origin and cannot fetch, load, or submit.
 *
 * A CSP delivered in a <meta> tag IGNORES `frame-ancestors`, `report-uri` and `sandbox`.
 * Do not add those here and believe they bind — the sandbox ATTRIBUTE on the parent
 * element is what carries that weight.
 *
 * == WHAT THIS DOES NOT COVER, said here rather than in a footnote ====================
 * PIXELS. Containment is perfect and irrelevant against a convincing fake sign-in form:
 * the frame renders one, it sits inside a page the visitor already trusts, and they type
 * their password into attacker HTML. `form-action 'none'` stops the submit, but a script
 * can still read the field, and the visitor has still typed their password into a box.
 * => The real control for that is STRUCTURAL and lives outside this file: credential
 *    entry must never happen inside a sandboxed pane. Sign-in belongs to your trusted
 *    chrome, and the code that mounts it should REFUSE to mount into one of these hosts.
 *    A paragraph in a design note is not a control.
 *
 * RESOURCE EXHAUSTION is accepted, not solved. Contained content can spin the CPU.
 * Annoying, visible, recoverable, bounded by the tab. Named so it is not a surprise;
 * deliberately not engineered against.
 *
 * REDACTION IS NOT CONTAINMENT. Scanning a body for things that look sensitive catches
 * only the forms somebody thought of. It is a useful reduction and it is not an isolation
 * claim. Containment is the provable control; do not let a filter imply otherwise.
 */
(function (global) {
  "use strict";

  // ONE ENTRY. Read it; the default denies everything else. Any addition here is a
  // security change and belongs in a commit whose first line says so.
  var SANDBOX = "allow-scripts";

  var CSP = [
    "default-src 'none'",          // connect-src omitted ON PURPOSE so it inherits this deny
    "script-src 'unsafe-inline'",  // inline IS the content; opaque origin, cannot fetch/load/submit
    "style-src 'unsafe-inline'",
    // A one-pixel <img> is a perfectly good beacon, so images get the same deny as
    // everything else. If inline imagery is ever needed, `data:` comes back as a
    // deliberate decision rather than as a leftover permission nobody re-examined.
    "img-src 'none'",
    "form-action 'none'",          // NOT covered by default-src — this one is about phishing
    "base-uri 'none'"
  ].join("; ");

  // What renders when a body was withheld. A VISIBLE refusal, never a blank pane: a pane
  // that silently shows nothing is indistinguishable from one that was never sent.
  var REFUSED = "— withheld —";

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  /* Build the full document that goes in the srcdoc.
   * THE CSP META MUST BE THE FIRST THING IN <head>. A policy that arrives after markup has
   * already been parsed does not govern that markup, so anything placed above it would run
   * UNPOLICED — and would look completely normal while doing so. */
  function srcdocFor(body, opts) {
    var style = (opts && opts.style) || "html,body{margin:0;padding:10px;"
      + "font:13px/1.5 ui-sans-serif,system-ui,sans-serif;background:transparent;overflow:auto}";
    return '<!doctype html><html><head>'
         + '<meta http-equiv="Content-Security-Policy" content="' + CSP + '">'
         + '<meta name="viewport" content="width=device-width,initial-scale=1">'
         + '<style>' + style + '</style>'
         + '</head><body>' + (body == null ? "" : String(body)) + '</body></html>';
  }

  /* The frame element itself. `srcdoc`, never `src`: the content never becomes a fetchable
   * URL on your origin, so it cannot be linked, indexed, or re-requested out of context. */
  function frameFor(body, label, opts) {
    var el = document.createElement("iframe");
    el.setAttribute("sandbox", SANDBOX);      // one entry — see the header before changing
    el.setAttribute("title", label ? String(label) : "sandboxed content");
    el.setAttribute("referrerpolicy", "no-referrer");
    /* NO `loading="lazy"`. It makes the frame's execution conditional on layout, which
       turns every containment assertion about the frame's BEHAVIOUR into a coin toss: an
       off-screen frame never runs, so "no beacon was sent" and "the frame never started"
       produce an identical trace — and the second one reads as a pass. A security check
       that goes green because the subject never woke up is worse than no check at all. */
    el.dataset.sandboxed = "1";
    // `== null` catches BOTH null and undefined — frameFor(undefined) must not fall
    // through to an empty body, which is the "silently empty pane" the design forbids.
    el.srcdoc = srcdocFor(body == null ? esc(REFUSED) : body, opts);
    return el;
  }

  /* A WEAK NET, NAMED AS WEAK. Scans a body for the obvious shape of a credential prompt
   * before injection. This is NOT the control — the control is structural (see the header:
   * credential entry never happens inside a sandboxed pane).
   * ITS LIMIT, stated so nobody mistakes it for the control: content can BUILD a password
   * field at runtime with one line of script, and `allow-scripts` is on by design. So it
   * catches the careless and the accidental and CANNOT catch the deliberate. A weak net
   * named as weak is fine; a weak net mistaken for the control is how a boundary quietly
   * stops existing.
   * It returns a REASON rather than a boolean, because a refusal that cannot say why
   * teaches the next reader nothing. */
  function looksLikeCredentialPrompt(body) {
    var t = String(body == null ? "" : body);
    if (/<input[^>]+type\s*=\s*["']?password/i.test(t)) return "a password input";
    if (/\bautocomplete\s*=\s*["']?(current|new)-password/i.test(t)) return "a password autocomplete hint";
    if (/<input[^>]+name\s*=\s*["']?(password|passwd|pwd)\b/i.test(t)) return "a password-named input";
    return null;
  }

  global.SandboxRender = {
    SANDBOX: SANDBOX, CSP: CSP, REFUSED: REFUSED,
    srcdocFor: srcdocFor, frameFor: frameFor, esc: esc,
    looksLikeCredentialPrompt: looksLikeCredentialPrompt
  };
  if (typeof module === "object" && module.exports) module.exports = global.SandboxRender;
})(typeof window !== "undefined" ? window : globalThis);
