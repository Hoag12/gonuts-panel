package panel

import (
	"strings"
	"testing"
)

func TestRewriteMakesPanelRelativeAndInjectsCSRF(t *testing.T) {
	in := `<head></head><img src="/logo.png"><form class="out" method="post" action="/logout"><button>Lock</button></form>
	<script>fetch('/state');fetch('/api/bots');fetch('/act');img.src='/item/minecraft:stone.png';n.src='/panel.png';all.href='https://gonuts.at/dashboard/bugs';website.href='https://gonuts.at/dashboard/'</script>`
	out := Rewrite(in, "csrf123")
	for _, bad := range []string{`src="/logo.png"`, `action="/logout"`, `fetch('/state')`, `fetch('/api/`, `fetch('/act')`, `src='/item/`, `src='/panel.png`, "gonuts.at"} {
		if strings.Contains(out, bad) {
			t.Fatalf("still contains %q:\n%s", bad, out)
		}
	}
	for _, want := range []string{`name="gonuts-csrf" content="csrf123"`, `src="logo.png"`, `action="/dashboard"`, `fetch('state')`, `fetch('api/bots')`, `fetch('act')`, `item/minecraft:stone.png`, `n.src='panel.png'`, `X-Gonuts-Csrf`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
}

func TestRewriteHandlesSpacedIconAssignmentAndFontURL(t *testing.T) {
	// The panel writes item icons as img.src = '/item/' + id + '.png'.
	in := `<html><head><title>p</title></head><body><style>@font-face{src:url(/font.ttf)}</style><script>img.src = '/item/' + 'minecraft:diamond' + '.png';</script></body></html>`
	out := Rewrite(in, "tok")
	if strings.Contains(out, `src = '/item/`) {
		t.Fatalf("spaced icon assignment not rewritten:\n%s", out)
	}
	if !strings.Contains(out, `src = 'item/' + 'minecraft:diamond' + '.png'`) {
		t.Fatalf("spaced icon assignment mangled:\n%s", out)
	}
	if strings.Contains(out, `url(/font.ttf)`) || !strings.Contains(out, `url(font.ttf)`) {
		t.Fatalf("font url not rewritten:\n%s", out)
	}
}

func TestRewriteInjectsBeforeHeadWhenHeadIsMissing(t *testing.T) {
	out := Rewrite(`<body><p>hi</p></body>`, "tok")
	if !strings.HasPrefix(out, `<meta name="gonuts-csrf" content="tok">`) {
		t.Fatalf("injection not prepended:\n%s", out)
	}
}

func TestRewriteEscapesCSRFAttribute(t *testing.T) {
	out := Rewrite(`<head></head>`, `a"b`)
	if strings.Contains(out, `content="a"b"`) {
		t.Fatalf("csrf value broke out of the attribute:\n%s", out)
	}
	if !strings.Contains(out, `content="a&#34;b"`) {
		t.Fatalf("csrf value not escaped:\n%s", out)
	}
}

func TestRewriteReplacesHostedTrackerURL(t *testing.T) {
	out := Rewrite(`<script>fetch('https://gonuts.at/dashboard/api/public/bugs')</script>`, "tok")
	if strings.Contains(out, "gonuts.at") {
		t.Fatalf("hosted tracker url survived:\n%s", out)
	}
	if !strings.Contains(out, `fetch('api/public/bugs')`) {
		t.Fatalf("tracker url not made relative:\n%s", out)
	}
}

func TestRewriteRemovesRetiredNoticeAndDefaultsToOwnAccount(t *testing.T) {
	in := `<body><section class="panel" role="note"><strong>PUBLIC SUPPORT HAS ENDED</strong>` +
		`<p>After seven weeks, GoNuts is no longer publicly maintained or supported.</p></section>` +
		`<select id="mobile-account"></select></body>`
	out := Rewrite(in, "tok")
	if strings.Contains(out, "PUBLIC SUPPORT HAS ENDED") || strings.Contains(out, "After seven weeks") {
		t.Fatalf("retired notice survived:\n%s", out)
	}
	if !strings.Contains(out, `\(this client\)`) || !strings.Contains(out, `mobile-account`) {
		t.Fatalf("split-panel account default not injected:\n%s", out)
	}
}
