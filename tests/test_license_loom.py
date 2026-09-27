import json,pytest
from test_harness import load
@pytest.fixture
def e(): return load('license_loom.py','LicenseLoom','policies')
def test_audit_receipt(e):
 _,c,q,b,U=e;c.register_policy('LIC-1','Demo','https://manifest.example/a','https://lock.example/a','["MIT","APACHE-2.0"]');bs=['{"license":"MIT"}','{"packages":[{"license":"MIT"}]}'];b.extend(bs+bs);q.extend(['{"status":"COMPLIANT","summary":"All licenses are allowed.","packages":[{"name":"demo","license":"MIT","reason":"Allowed by policy."}]}']*2);c.audit_policy('lic-1');r=json.loads(c.get_policy('0xowner','LIC-1'));assert r['state']=='AUDITED' and r['status']=='COMPLIANT' and len(r['digests'])==2
def test_guards(e):
 _,c,q,b,U=e
 with pytest.raises(U): c.register_policy('LIC-1','Demo','https://same.example/a','https://same.example/b','["MIT"]')
 with pytest.raises(U): c.register_policy('LIC-1','Demo','https://a.example/a','https://b.example/b','[]')
 c.register_policy('LIC-1','Demo','https://a.example/a','https://b.example/b','["MIT"]')
 with pytest.raises(U): c.register_policy(' lic-1 ','Demo','https://c.example/a','https://d.example/b','["MIT"]')
def test_forged_validator_rejected(e):
 _,c,q,b,U=e;c.register_policy('LIC-2','Demo','https://a.example/a','https://b.example/b','["MIT"]');bs=['manifest evidence with MIT','lock evidence with MIT'];b.extend(bs+bs);q.extend(['{"status":"INCOMPATIBLE","summary":"GPL is not allowed.","packages":[{"name":"x","license":"GPL-3.0","reason":"Not allowed."}]}','{"status":"COMPLIANT","summary":"forged","packages":[]}'])
 with pytest.raises(U): c.audit_policy('LIC-2')
