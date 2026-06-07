package main

import "net/http"

func page(html string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(html))
	}
}

// homeHTML shows the current RP session (after SSO login) or a link to sign in.
const homeHTML = `<!doctype html><meta charset=utf-8><title>Demo RP</title>
<style>body{font:16px system-ui;max-width:34rem;margin:5rem auto;padding:0 1rem}
pre{background:#f4f4f4;padding:1rem;border-radius:8px;overflow:auto}a{color:#2563eb}</style>
<h1>Demo Relying Party</h1>
<div id=out><p>Checking session…</p></div>
<script>
fetch("/api/auth/session",{credentials:"include"}).then(r=>r.ok?r.json():null).then(s=>{
  if(s&&s.user){out.innerHTML="<p>✅ Signed in as <b>"+s.user.email+"</b> (role "+(s.user.role||"?")+")</p>"+
    "<pre>"+JSON.stringify(s.user,null,2)+"</pre><p><a href=/api/auth/logout>Log out</a></p>";}
  else{out.innerHTML="<p>Not signed in.</p><p><a href=/login>Go to sign in</a></p>";}
}).catch(()=>{out.innerHTML="<p><a href=/login>Go to sign in</a></p>";});
</script>`

// loginHTML offers local email/password plus the one-click SSO button.
const loginHTML = `<!doctype html><meta charset=utf-8><title>RP · Sign in</title>
<style>body{font:16px system-ui;max-width:24rem;margin:5rem auto;padding:0 1rem}
input{display:block;width:100%;padding:.6rem;margin:.4rem 0;box-sizing:border-box}
button,.btn{padding:.6rem 1rem;width:100%;cursor:pointer;display:block;box-sizing:border-box;
  text-align:center;text-decoration:none;border:1px solid #ccc;border-radius:6px;margin:.4rem 0;color:#111}
.sso{background:#111;color:#fff;border-color:#111}.err{color:#c00}.or{color:#888;text-align:center;margin:.6rem 0}</style>
<h1>Demo RP — Sign in</h1>
<a class="btn sso" id=sso href="/api/auth/sso/login?org=demo&redirect=http://127.0.0.1:8080/">Sign in with the Demo IdP</a>
<p class=or>or</p>
<form id=f>
  <input id=email name=email type=email placeholder=email autocomplete=username>
  <input id=password name=password type=password placeholder=password autocomplete=current-password>
  <button id=submit type=submit>Sign in locally</button>
  <p class=err id=err></p>
</form>
<script>
f.addEventListener("submit",async e=>{
  e.preventDefault(); err.textContent="";
  const res=await fetch("/api/auth/login",{method:"POST",credentials:"include",
    headers:{"content-type":"application/json"},
    body:JSON.stringify({email:email.value,password:password.value})});
  if(res.ok){location.href="/";}else{err.textContent="Sign in failed ("+res.status+")";}
});
</script>`
