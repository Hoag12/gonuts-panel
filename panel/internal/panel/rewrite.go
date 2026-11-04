// Package panel rewrites the mod's own panel page for hosting behind the
// relay. The page is the mod's Pages.APP; only URL and CSRF plumbing changes,
// so the layout, text, and behaviour the user sees stay identical.
package panel

import (
	"html"
	"regexp"
	"strings"
)

// rewriteReplacer turns the panel's absolute, mod-rooted URLs into paths
// relative to the hosted panel URL, and turns the "Lock" form into a GET back
// to the dashboard. The hosted panel must never post a logout, because the
// dashboard session is not the mod's local login.
var rewriteReplacer = strings.NewReplacer(
	`src="/logo.png"`, `src="logo.png"`,
	`src='/panel.png`, `src='panel.png`,
	`src='/item/`, `src='item/`,
	`src = '/item/'`, `src = 'item/'`,
	`fetch('/state'`, `fetch('state'`,
	`fetch('/api/`, `fetch('api/`,
	`fetch('/act'`, `fetch('act'`,
	`fetch('https://gonuts.at/dashboard/api/public/bugs'`, `fetch('api/public/bugs'`,
	`https://gonuts.at/dashboard/bugs`, `/dashboard`,
	`https://gonuts.at/dashboard/`, `/dashboard`,
	`url(/font.ttf)`, `url(font.ttf)`,
	`<form class="out" method="post" action="/logout">`, `<form class="out" method="get" action="/dashboard">`,
)

// csrfWrapper is injected before the panel's own scripts. It reads the token
// from the meta tag and adds the CSRF header to every same-origin fetch. The
// panel's script already sends X-GoNuts: 1 on mutations; the wrapper only adds
// the token so a hosted panel can satisfy the relay's mutation checks.
const csrfWrapper = `<script>(function(){` +
	`var t=document.querySelector('meta[name="gonuts-csrf"]').content;` +
	`var f=window.fetch.bind(window);` +
	`window.fetch=function(u,o){o=o||{};var s=typeof u==='string'?u:u.url;` +
	`if(!/^[a-z]+:/i.test(s)){var h=new Headers(o.headers||{});h.set('X-Gonuts-Csrf',t);o.headers=h;}` +
	`return f(u,o);};` +
	`})();</script>`

// retiredNotice matches the mod's "public support has ended" section. The
// self-hosted panel keeps working, so that notice is not true here.
var retiredNotice = regexp.MustCompile(`(?s)<section[^>]*role="note"[^>]*>.*?</section>`)

// autoAccountScript selects the "(this client)" account in the panel's hidden
// account picker. In a split/multi-client setup each instance owns one account,
// and older mod builds otherwise open on "all accounts · hive of 2". New mod
// builds remove the picker entirely; this is a no-op there.
const autoAccountScript = `<script>(function(){` +
	`function pick(){var s=document.getElementById('mobile-account');if(!s||!s.options)return;` +
	`for(var i=0;i<s.options.length;i++){var o=s.options[i];` +
	`if(/\(this client\)/i.test(o.textContent)&&s.value!==o.value){s.value=o.value;` +
	`s.dispatchEvent(new Event('change'));return;}}}` +
	`setInterval(pick,1200);})();</script>`

// imageFallbackScript keeps the summary visible when the panel preview transfer
// stalls. The panel page's preview path can leave its image pending on a busy
// bot; /panel.png (and the relay's SVG fallback) still answers.
const imageFallbackScript = `<script>(function(){` +
	`function image(){var s=document.getElementById('shot');if(!s||!s.hidden)return;` +
	`var i=new Image();i.onload=function(){s.src=i.src;s.hidden=false;` +
	`var t=document.getElementById('image-status');if(t)t.textContent='Summary loaded from the live panel.';};` +
	`i.src='panel.png?t='+Date.now();}` +
	`setInterval(image,8000);})();</script>`

// Rewrite makes the panel page relative to its hosted URL, redirects its Lock
// form to the dashboard, removes the retired notice, and injects the
// per-session CSRF token plus the split-panel account default.
//
// The same rewritten page is safe to share between sessions because the token
// is only ever injected here, per request; callers cache the raw page.
func Rewrite(page, csrf string) string {
	page = rewriteReplacer.Replace(page)
	page = retiredNotice.ReplaceAllStringFunc(page, func(block string) string {
		if strings.Contains(block, "PUBLIC SUPPORT HAS ENDED") {
			return ""
		}
		return block
	})
	inject := `<meta name="gonuts-csrf" content="` + html.EscapeString(csrf) + `">` + csrfWrapper + autoAccountScript + imageFallbackScript
	if i := indexFoldASCII(page, "<head>"); i >= 0 {
		page = page[:i+len("<head>")] + inject + page[i+len("<head>"):]
	} else {
		page = inject + page
	}
	return page
}

// indexFoldASCII finds sub in s, ignoring ASCII case. It returns a byte offset
// that is valid for s, unlike comparing against strings.ToLower(s), whose
// length can change for non-ASCII runes.
func indexFoldASCII(s, sub string) int {
	n := len(sub)
	for i := 0; i+n <= len(s); i++ {
		if strings.EqualFold(s[i:i+n], sub) {
			return i
		}
	}
	return -1
}
