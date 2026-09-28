const { test, describe } = require("node:test");
const assert = require("node:assert/strict");

// the smallest DOM the library touches: createElement + setAttribute + dataset
globalThis.window = globalThis;
globalThis.document = {
  createElement(tag) {
    return { tagName: String(tag).toUpperCase(), attributes: {}, dataset: {},
             setAttribute(k, v) { this.attributes[k] = String(v); },
             getAttribute(k) { return k in this.attributes ? this.attributes[k] : null; } };
  }
};
const SR = require("../sandbox-render.js");

describe("the sandbox attribute — the whole control", () => {
  test("is exactly one entry", () => {
    assert.equal(SR.SANDBOX, "allow-scripts");
    assert.equal(SR.SANDBOX.trim().split(/\s+/).length, 1);
  });
  test("NEVER carries allow-same-origin — the pair defeats the sandbox entirely", () => {
    assert.ok(!/allow-same-origin/.test(SR.SANDBOX),
      "allow-scripts + allow-same-origin lets a frame remove its own sandbox attribute");
  });
  test("carries none of the other permissive tokens", () => {
    for (const t of ["allow-top-navigation", "allow-popups", "allow-modals",
                     "allow-forms", "allow-pointer-lock", "allow-downloads",
                     "allow-popups-to-escape-sandbox", "allow-presentation"])
      assert.ok(!SR.SANDBOX.includes(t), `sandbox must not include ${t}`);
  });
});

describe("the CSP", () => {
  const d = SR.CSP.split(";").map(s => s.trim());
  test("denies everything by default", () => {
    assert.ok(d.includes("default-src 'none'"));
  });
  test("omits connect-src ON PURPOSE so fetch/XHR/WebSocket/sendBeacon inherit the deny", () => {
    assert.ok(!SR.CSP.includes("connect-src"),
      "adding connect-src would override the default-src deny for network calls");
  });
  test("states the two directives default-src does NOT cover", () => {
    assert.ok(d.includes("form-action 'none'"), "form POST is not governed by default-src");
    assert.ok(d.includes("base-uri 'none'"), "a <base> tag would re-point relative URLs");
  });
  test("denies images — a one-pixel img is a working beacon", () => {
    assert.ok(d.includes("img-src 'none'"));
    assert.ok(!/img-src[^;]*data:/.test(SR.CSP), "no leftover data: permission");
    assert.ok(!/img-src[^;]*https?:/.test(SR.CSP));
  });
  test("allows inline script and style, which is the content itself", () => {
    assert.ok(d.includes("script-src 'unsafe-inline'"));
    assert.ok(d.includes("style-src 'unsafe-inline'"));
  });
  test("carries no directive that a <meta> CSP silently ignores", () => {
    for (const ignored of ["frame-ancestors", "report-uri", "report-to", "sandbox"])
      assert.ok(!SR.CSP.includes(ignored),
        `${ignored} does not bind from a meta tag and would be false reassurance`);
  });
  test("names no remote host anywhere", () => {
    assert.ok(!/https?:\/\//.test(SR.CSP));
    assert.ok(!/\*/.test(SR.CSP), "no wildcard sources");
  });
});

describe("srcdocFor — document assembly", () => {
  test("the CSP meta is the FIRST element in head", () => {
    const doc = SR.srcdocFor("<p>hi</p>");
    const head = doc.slice(doc.indexOf("<head>") + 6, doc.indexOf("</head>"));
    assert.ok(head.trimStart().startsWith('<meta http-equiv="Content-Security-Policy"'),
      "markup above the policy would parse unpoliced");
  });
  test("the policy embedded is the exported one, verbatim", () => {
    assert.ok(SR.srcdocFor("").includes('content="' + SR.CSP + '"'));
  });
  test("the body is placed inside <body>, after the policy", () => {
    const doc = SR.srcdocFor("<p>marker</p>");
    assert.ok(doc.indexOf("<p>marker</p>") > doc.indexOf("Content-Security-Policy"));
    assert.ok(doc.indexOf("<p>marker</p>") > doc.indexOf("<body>"));
  });
  test("null and undefined bodies produce a valid empty document, not the string 'null'", () => {
    for (const v of [null, undefined]) {
      const doc = SR.srcdocFor(v);
      assert.ok(doc.includes("<body></body>"), `body for ${v}`);
      assert.ok(!doc.includes("undefined") && !/>\s*null\s*</.test(doc));
    }
  });
  test("content is NOT escaped — the frame renders real markup, that is the point", () => {
    assert.ok(SR.srcdocFor("<b>bold</b>").includes("<b>bold</b>"));
  });
  test("a caller may override the frame stylesheet without touching the policy", () => {
    const doc = SR.srcdocFor("x", { style: "body{color:red}" });
    assert.ok(doc.includes("body{color:red}"));
    assert.ok(doc.includes(SR.CSP), "overriding style must not drop the policy");
  });
});

describe("frameFor — the element", () => {
  test("carries the one-entry sandbox", () => {
    assert.equal(SR.frameFor("x").getAttribute("sandbox"), "allow-scripts");
  });
  test("uses srcdoc and never src, so the content is not a fetchable URL", () => {
    const f = SR.frameFor("<p>x</p>");
    assert.ok(f.srcdoc.includes("<p>x</p>"));
    assert.equal(f.getAttribute("src"), null);
  });
  test("sends no referrer", () => {
    assert.equal(SR.frameFor("x").getAttribute("referrerpolicy"), "no-referrer");
  });
  test("is NOT lazy-loaded — a frame that never runs fakes a passing containment check", () => {
    assert.equal(SR.frameFor("x").getAttribute("loading"), null);
  });
  test("labels itself, and takes a caller label", () => {
    assert.equal(SR.frameFor("x").getAttribute("title"), "sandboxed content");
    assert.equal(SR.frameFor("x", "chart").getAttribute("title"), "chart");
  });
  test("a withheld (null) body renders a VISIBLE refusal, not a blank pane", () => {
    const f = SR.frameFor(null);
    assert.ok(f.srcdoc.includes(SR.REFUSED));
    assert.notEqual(SR.REFUSED.trim(), "");
  });
  test("a withheld (undefined) body ALSO renders the visible refusal, not a blank pane", () => {
    assert.ok(SR.frameFor(undefined).srcdoc.includes(SR.REFUSED));
  });
  test("an empty-string body is distinct from a withheld body", () => {
    assert.ok(!SR.frameFor("").srcdoc.includes(SR.REFUSED));
  });
});

describe("esc", () => {
  test("neutralizes the three characters that open a tag", () => {
    assert.equal(SR.esc('<script>&"'), '&lt;script&gt;&amp;"');
  });
  test("escapes the ampersand FIRST, so escapes are not double-escaped", () => {
    assert.equal(SR.esc("&lt;"), "&amp;lt;");
  });
  test("null and undefined become empty, not the words", () => {
    assert.equal(SR.esc(null), ""); assert.equal(SR.esc(undefined), "");
  });
});

describe("looksLikeCredentialPrompt — a weak net, named as weak", () => {
  const L = SR.looksLikeCredentialPrompt;
  test("catches a password input and says which form it matched", () => {
    assert.equal(L('<input type="password">'), "a password input");
    assert.equal(L("<input type=password>"), "a password input");
  });
  test("catches a password autocomplete hint", () => {
    assert.equal(L('<input autocomplete="current-password">'), "a password autocomplete hint");
    assert.equal(L('<input autocomplete="new-password">'), "a password autocomplete hint");
  });
  test("catches a password-named input", () => {
    for (const n of ["password", "passwd", "pwd"])
      assert.equal(L(`<input name="${n}">`), "a password-named input");
  });
  test("is case-insensitive", () => {
    assert.equal(L('<INPUT TYPE="PASSWORD">'), "a password input");
  });
  test("returns null for ordinary content, and for nothing at all", () => {
    assert.equal(L("<p>hello</p>"), null);
    assert.equal(L('<input type="text" name="city">'), null);
    assert.equal(L(null), null); assert.equal(L(""), null);
  });
  test("returns a REASON string, never a bare boolean", () => {
    assert.equal(typeof L('<input type="password">'), "string");
  });
  // The documented limit, asserted so it stays true rather than living only in a comment.
  test("DOES NOT catch a field built at runtime — the stated limit, proven", () => {
    const built = `<script>
      const i = document.createElement('input');
      i.type = 'pass' + 'word';
      document.body.appendChild(i);
    </script>`;
    assert.equal(L(built), null,
      "this is why the real control is structural, not this filter");
  });
});

describe("exported surface", () => {
  test("everything documented is present", () => {
    for (const k of ["SANDBOX","CSP","REFUSED","srcdocFor","frameFor","esc","looksLikeCredentialPrompt"])
      assert.ok(k in SR, `missing ${k}`);
  });
  test("the constants are strings a caller can inspect and assert on", () => {
    assert.equal(typeof SR.SANDBOX, "string");
    assert.equal(typeof SR.CSP, "string");
  });
});
