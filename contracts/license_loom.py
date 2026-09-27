# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""Consensus-backed open-source license compatibility receipt."""
from genlayer import *
from urllib.parse import urlparse
import hashlib, json, re

def enc(v): return json.dumps(v, sort_keys=True, separators=(",", ":"))
def ident(v):
    v=v.strip().upper()
    if not 3<=len(v)<=64 or not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in v): raise gl.vm.UserError("invalid policy ID")
    return v
def https(v):
    p=urlparse(v.strip())
    if p.scheme!="https" or not p.hostname or p.username or p.password or p.fragment: raise gl.vm.UserError("clean HTTPS URL required")
    return v.strip()
def allowed(raw):
    x=json.loads(raw)
    if type(x) is not list or not 1<=len(x)<=40: raise ValueError("allowed licenses required")
    y=sorted({str(v).upper().strip() for v in x})
    if any(not 2<=len(v)<=40 for v in y): raise ValueError("invalid license")
    return y
def verdict(raw):
    x=json.loads(raw)
    if type(x) is not dict or set(x)!={"status","summary","packages"} or x["status"] not in ("COMPLIANT","INCOMPATIBLE","UNKNOWN"): raise ValueError("bad verdict")
    if not isinstance(x["packages"],list) or len(x["packages"])>100: raise ValueError("bad packages")
    clean=[]
    for p in x["packages"]:
        if type(p) is not dict or set(p)!={"name","license","reason"}: raise ValueError("bad package")
        clean.append({"name":str(p["name"])[:120],"license":str(p["license"]).upper()[:40],"reason":str(p["reason"])[:220]})
    return {"status":x["status"],"summary":str(x["summary"])[:400],"packages":clean}
def assess(packet):
    """Deterministic license extraction after the two nondeterministic fetches."""
    known=("MIT","APACHE-2.0","GPL-3.0","GPL-2.0","BSD-3-CLAUSE","BSD-2-CLAUSE","ISC","MPL-2.0")
    found=[]
    def walk(v,name="project"):
        if isinstance(v,dict):
            lic=v.get("license")
            nm=str(v.get("name",name))[:120]
            if isinstance(lic,str): found.append((nm,lic.upper().strip()))
            for k,x in v.items(): walk(x,nm if k=="dependencies" else name)
        elif isinstance(v,list):
            for x in v: walk(x,name)
    for body in (packet["manifest"],packet["lock"]):
        try: walk(json.loads(body),packet["project"])
        except Exception: pass
        upper=body.upper()
        for token in known:
            if token in upper and not any(x[1]==token for x in found): found.append((packet["project"],token))
    if not found:
        return {"status":"UNKNOWN","summary":"sources do not expose a machine-readable license","packages":[]}
    packages=[]; incompatible=False
    for name,lic in found[:100]:
        ok=lic in packet["allowed"]
        incompatible=incompatible or not ok
        packages.append({"name":name,"license":lic,"reason":"allowed by policy" if ok else "not present in the allowed license set"})
    return {"status":"INCOMPATIBLE" if incompatible else "COMPLIANT","summary":"all discovered licenses comply" if not incompatible else "one or more discovered licenses are outside policy","packages":packages}

class LicenseLoom(gl.Contract):
    policies: TreeMap[str,str]
    def __init__(self): pass
    def key(self,o,i): return str(o).lower()+":"+ident(i)
    @gl.public.write
    def register_policy(self,policy_id:str,project:str,manifest_url:str,lock_url:str,allowed_licenses_json:str)->None:
        owner=str(gl.message.sender_address).lower(); key=self.key(owner,policy_id)
        if self.policies.get(key,""): raise gl.vm.UserError("policy ID already exists")
        urls=[https(manifest_url),https(lock_url)]
        if urlparse(urls[0]).hostname==urlparse(urls[1]).hostname: raise gl.vm.UserError("sources need distinct hosts")
        try: allow=allowed(allowed_licenses_json)
        except Exception: raise gl.vm.UserError("invalid allowed license list")
        self.policies[key]=enc({"id":ident(policy_id),"owner":owner,"project":str(project).strip()[:160],"manifest":urls[0],"lock":urls[1],"allowed":allow,"state":"OPEN","status":"","summary":"","packages":[],"digests":[]})
    @gl.public.write
    def audit_policy(self,policy_id:str)->None:
        key=self.key(str(gl.message.sender_address),policy_id); r=json.loads(self.policies.get(key,"{}"))
        if not r or r["state"]!="OPEN": raise gl.vm.UserError("policy is not open")
        def run():
            bodies=[gl.nondet.web.get(u).body.decode("utf-8") for u in (r["manifest"],r["lock"])]
            if not all(2<=len(v)<=100000 for v in bodies): raise gl.vm.UserError("license source unavailable")
            out=assess({"project":r["project"],"allowed":r["allowed"],"manifest":bodies[0],"lock":bodies[1]})
            return enc({**out,"digests":[hashlib.sha256(v.encode()).hexdigest() for v in bodies]})
        def valid(x):
            if not isinstance(x,gl.vm.Return): return False
            try:
                bodies=[gl.nondet.web.get(u).body.decode("utf-8") for u in (r["manifest"],r["lock"])]
                out=assess({"project":r["project"],"allowed":r["allowed"],"manifest":bodies[0],"lock":bodies[1]})
                return json.loads(x.calldata)=={**out,"digests":[hashlib.sha256(v.encode()).hexdigest() for v in bodies]}
            except Exception: return False
        r.update(json.loads(gl.vm.run_nondet_unsafe(run,valid))); r["state"]="AUDITED"; self.policies[key]=enc(r)
    @gl.public.view
    def get_policy(self,owner:str,policy_id:str)->str: return self.policies.get(self.key(owner,policy_id),"{}")
