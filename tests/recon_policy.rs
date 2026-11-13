use llm_pipeline_tools::recon::policy::Policy;
use serde_json::{Value,json};
use sha2::{Digest,Sha256};
use std::net::IpAddr;
use std::os::unix::fs::{PermissionsExt,symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize,Ordering};

fn policy(extra: Value) -> Policy {
    let mut value = json!({"v":1,"in_scope":{"suffixes":["example.test"]}});
    for (key,value_extra) in extra.as_object().unwrap() { value[key] = value_extra.clone(); }
    Policy::from_json(&serde_json::to_vec(&value).unwrap()).unwrap()
}
#[test]
fn explicit_denies_win_with_case_and_label_boundaries() {
    let policy = policy(json!({"out_of_scope":{"hosts":["secret.example.test"],"suffixes":["internal.example.test"]}}));
    for host in ["example.test","www.example.test","WWW.EXAMPLE.TEST.","notinternal.example.test"] { assert!(policy.permits_host(host),"{host}"); }
    for host in ["secret.example.test","internal.example.test","x.internal.example.test","notexample.test","example.test.evil.test"] { assert!(!policy.permits_host(host),"{host}"); }
}
#[test]
fn default_private_non_global_mapped_and_mixed_sets_are_denied() {
    let policy = policy(json!({}));
    let public: IpAddr = "8.8.8.8".parse().unwrap();
    for address in ["127.0.0.1","10.0.0.1","172.16.0.1","192.168.0.1","169.254.169.254","100.64.0.1","0.0.0.0","192.0.2.1","224.0.0.1","::1","::","fc00::1","fe80::1","ff02::1","::ffff:127.0.0.1","::ffff:192.168.0.1","2001:db8::1","2002:7f00:1::1"] {
        let private = address.parse().unwrap();
        assert!(policy.check_resolution("app.example.test",&[private],&[]).is_err(),"{address}");
        assert!(policy.check_resolution("app.example.test",&[public,private],&[]).is_err(),"mixed {address}");
    }
    assert!(policy.check_resolution("app.example.test",&[public,"2606:4700:4700::1111".parse().unwrap()],&[]).is_ok());
}
#[test]
fn internal_opt_in_does_not_disable_explicit_cidr_denies() {
    let policy = policy(json!({"deny_private_ips":false,"out_of_scope":{"cidrs":["10.2.0.0/16","127.0.0.0/8","2001:db8::/32"]}}));
    assert!(policy.check_resolution("app.example.test",&["10.3.0.1".parse().unwrap()],&[]).is_ok());
    for ip in ["10.2.0.1","::ffff:10.2.0.1","127.0.0.1","2001:db8::1"] {
        assert!(policy.check_resolution("app.example.test",&[ip.parse().unwrap()],&[]).is_err(),"{ip}");
    }
}
#[test]
fn provider_guards_are_explicit_not_infrastructure_heuristics() {
    let policy = policy(json!({"provider_cname_denylist":["provider.test"]}));
    let ips = ["8.8.8.8".parse().unwrap()];
    for cname in ["provider.test","tenant.provider.test","TENANT.PROVIDER.TEST."] {
        assert_eq!(policy.disposition("app.example.test",&ips,&[cname.into()]),"blocked_cname");
    }
    for cname in ["notprovider.test","provider.test.evil.test","unrelated.cdn.test"] {
        assert!(policy.check_resolution("app.example.test",&ips,&[cname.into()]).is_ok());
    }
}
#[test]
fn exact_required_headers_fail_without_leaking_required_values() {
    let policy = policy(json!({"required_headers":{"X-Research-Id":"secret-value"}}));
    let missing = policy.http_headers().unwrap_err();
    assert!(missing.contains("x-research-id"));
    assert!(!missing.contains("secret-value"));
    let wrong = policy.with_http_headers(r#"{"x-research-id":"wrong"}"#).unwrap();
    assert!(wrong.http_headers().is_err());
    let exact = wrong.with_http_headers(r#"{"X-Research-Id":"secret-value"}"#).unwrap();
    assert_eq!(exact.http_headers().unwrap()["x-research-id"],"secret-value");
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!("recon-policy-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed)));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
#[test]
fn readable_protected_files_hash_the_exact_opened_bytes() {
    let fixture = Fixture::new();
    let path = fixture.0.join("scope.json");
    let bytes = b"{\n  \"v\":1,\"in_scope\":{\"hosts\":[\"app.example.test\"]}\n}\n";
    std::fs::write(&path,bytes).unwrap();
    std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o644)).unwrap();
    let loaded = Policy::from_file(&path).unwrap();
    assert_eq!(loaded.fingerprint(),Some(format!("{:x}",Sha256::digest(bytes)).as_str()));
    assert!(loaded.permits_host("app.example.test"));
    std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(Policy::from_file(&path).is_ok());
    std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o664)).unwrap();
    assert!(Policy::from_file(&path).is_err());
    std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = fixture.0.join("symlink.json");
    symlink(&path,&link).unwrap();
    assert!(Policy::from_file(&link).is_err());
    assert!(Policy::from_file(&fixture.0).is_err());
    assert!(Policy::from_file(std::path::Path::new("scope.json")).is_err());
}
#[test]
fn strict_version_names_cidrs_and_rate_configuration() {
    for value in [
        json!({"v":2,"in_scope":{}}),json!({"v":1,"in_scope":{},"unknown":true}),
        json!({"v":1,"in_scope":{"suffixes":["*.example.test"]}}),json!({"v":1,"in_scope":{"suffixes":["127.0.0.1"]}}),
        json!({"v":1,"in_scope":{},"out_of_scope":{"cidrs":["10.0.0.0/33"]}}),
        json!({"v":1,"in_scope":{},"max_rps":0}),json!({"v":1,"in_scope":{},"max_rps":3}),
        json!({"v":1,"in_scope":{},"required_headers":{"Authorization":"forbidden"}}),
    ] { assert!(Policy::from_json(&serde_json::to_vec(&value).unwrap()).is_err(),"{value}"); }
    assert_eq!(policy(json!({"max_rps":0.5})).request_interval(),std::time::Duration::from_secs(2));
}

#[test]
fn operator_environment_requirements_merge_without_affecting_passive_startup() {
    let fixture = Fixture::new();
    let path = fixture.0.join("scope.json");
    std::fs::write(&path,br#"{"v":1,"in_scope":{"hosts":["app.example.test"]},"required_headers":{"X-Research-Id":"scope-value"}}"#).unwrap();
    std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();
    for scenario in ["presence","exact","conflict","require_scope"] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact","operator_environment_child","--ignored","--nocapture"]);
        for name in ["RECON_SCOPE","RECON_REQUIRE_SCOPE","RECON_REQUIRED_HEADER","RECON_REQUIRED_HEADERS","RECON_HTTP_HEADERS"] { command.env_remove(name); }
        command.env("RECON_POLICY_SCENARIO",scenario);
        match scenario {
            "presence" => { command.env("RECON_REQUIRED_HEADER","X-Research-Id"); }
            "exact" => { command.env("RECON_SCOPE",&path).env("RECON_REQUIRED_HEADER","X-Research-Id")
                .env("RECON_REQUIRED_HEADERS",r#"{"x-research-id":"scope-value","x-case":"123"}"#)
                .env("RECON_HTTP_HEADERS",r#"{"X-Research-Id":"scope-value","X-Case":"123"}"#); }
            "conflict" => { command.env("RECON_SCOPE",&path).env("RECON_REQUIRED_HEADERS",r#"{"x-research-id":"conflicting-secret"}"#); }
            "require_scope" => { command.env("RECON_REQUIRE_SCOPE","1"); }
            _ => unreachable!(),
        }
        let output = command.output().unwrap();
        assert!(output.status.success(),"{scenario}: {}",String::from_utf8_lossy(&output.stdout));
    }
}
#[test]
#[ignore = "isolated environment child, launched by regression test"]
fn operator_environment_child() {
    match std::env::var("RECON_POLICY_SCENARIO").unwrap().as_str() {
        "presence" => {
            assert!(llm_pipeline_tools::recon::policy::validate_startup().is_ok());
            let policy = Policy::load().unwrap();
            assert!(policy.check_network().is_ok());
            assert!(policy.check_http().unwrap_err().contains("x-research-id"));
        }
        "exact" => {
            let policy = Policy::load().unwrap();
            assert_eq!(policy.http_headers().unwrap()["x-case"],"123");
        }
        "conflict" => {
            let error = Policy::load().err().unwrap();
            assert!(error.contains("x-research-id"));
            assert!(!error.contains("conflicting-secret"));
            assert!(!error.contains("scope-value"));
        }
        "require_scope" => {
            let policy = Policy::load().unwrap();
            assert!(policy.check_network().is_err());
            assert!(policy.check_http().is_err());
        }
        _ => unreachable!(),
    }
}
