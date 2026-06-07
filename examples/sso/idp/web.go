package main

import (
	"net/http"
)

// page serves a static HTML string.
func page(html string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(html))
	}
}

const homeHTML = `<!doctype html><meta charset=utf-8><title>Demo IdP</title>
<style>body{font:16px system-ui;max-width:38rem;margin:4rem auto;padding:0 1rem}code{background:#eee;padding:.1em .3em;border-radius:4px}</style>
<h1>Demo IdP</h1><p>This is the identity provider for the yauth→yauth SSO example.</p>
<p><a href="/login">Sign in</a></p>`

// loginHTML posts to the email-password login API, then returns to ?return=.
const loginHTML = `<!doctype html><meta charset=utf-8><title>IdP · Sign in</title>
<style>body{font:16px system-ui;max-width:24rem;margin:5rem auto;padding:0 1rem}
input{display:block;width:100%;padding:.6rem;margin:.4rem 0;box-sizing:border-box}
button{padding:.6rem 1rem;width:100%;cursor:pointer}.err{color:#c00}</style>
<h1>Demo IdP — Sign in</h1>
<form id=f>
  <input id=email name=email type=email placeholder=email value="user@demo.test" autocomplete=username>
  <input id=password name=password type=password placeholder=password autocomplete=current-password>
  <button id=submit type=submit>Sign in</button>
  <p class=err id=err></p>
</form>
<script>
const p=new URLSearchParams(location.search), ret=p.get("return")||"/";
f.addEventListener("submit",async e=>{
  e.preventDefault(); err.textContent="";
  const res=await fetch("/api/auth/login",{method:"POST",credentials:"include",
    headers:{"content-type":"application/json"},
    body:JSON.stringify({email:email.value,password:password.value})});
  if(res.ok){location.href=ret;}else{err.textContent="Sign in failed ("+res.status+")";}
});
</script>`

// consentHTML drives GET /oauth/authorize then POST /oauth2/consent, mirroring
// the production OAuthConsentPage but minimal.
const consentHTML = `<!doctype html><meta charset=utf-8><title>IdP · Authorize</title>
<style>body{font:16px system-ui;max-width:26rem;margin:5rem auto;padding:0 1rem}
button{padding:.6rem 1rem;margin:.3rem .3rem 0 0;cursor:pointer}.muted{color:#666}.err{color:#c00}
ul{padding-left:1.1rem}</style>
<h1 id=title>Authorize</h1>
<div id=body><p class=muted>Loading…</p></div>
<script>
const qs=location.search.substring(1);
async function start(){
  const res=await fetch("/api/auth/oauth/authorize?"+qs,{credentials:"include"});
  if(res.status===401||res.status===403){location.href="/login?return="+encodeURIComponent(location.href);return;}
  const data=await res.json().catch(()=>({}));
  if(data.redirect_url){location.href=data.redirect_url;return;} // already consented
  render(data);
}
function render(d){
  const scopes=(d.scopes||[]).map(s=>"<li>"+s+"</li>").join("");
  body.innerHTML='<p><b>'+((d.client&&d.client.name)||"An app")+'</b> wants to access your account:</p>'+
    '<ul>'+scopes+'</ul>'+
    '<button id=approve>Approve</button><button id=deny>Deny</button><p class=err id=err></p>';
  approve.onclick=()=>decide(d,true); deny.onclick=()=>decide(d,false);
}
async function decide(d,ok){
  const res=await fetch("/api/auth/oauth2/consent",{method:"POST",credentials:"include",
    headers:{"content-type":"application/json"},
    body:JSON.stringify({request_id:d.request_id,csrf_token:d.csrf_token,approved:ok})});
  const out=await res.json().catch(()=>({}));
  if(out.redirect_url){location.href=out.redirect_url;}else{err.textContent="Consent failed ("+res.status+")";}
}
start();
</script>`
