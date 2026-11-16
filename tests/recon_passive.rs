// Exercise private pure/IO boundaries without exposing a production fixture API.
pub use llm_pipeline_tools::{Result, sha256};
mod recon { pub use llm_pipeline_tools::recon::{audit, network, policy, result, types}; }
#[allow(dead_code)]
mod implementation {
include!("../src/recon/passive.rs");

#[cfg(test)]
mod tests {
    use super::*;

    fn domain() -> Domain { Domain::parse("example.com").unwrap() }
    fn web(path: &str) -> WebUrl { WebUrl::parse(&format!("https://example.com{path}")).unwrap() }
    fn response(status: u16, mime: &str, body: &str) -> network::Fetch {
        network::Fetch { status,headers:BTreeMap::from([("content-type".into(),mime.into())]),
            body:body.as_bytes().to_vec(),truncated:false,read_error:None }
    }
    type Routes = BTreeMap<String,(u16,String,String)>;
    fn routes(entries: &[(&str,u16,&str,&str)]) -> Routes {
        entries.iter().map(|(path,status,mime,body)|(path.to_string(),(*status,mime.to_string(),body.to_string()))).collect()
    }
    fn harness(checkpoint: Option<&CrawlCheckpoint>, limit: usize, routes: Routes)
        -> (Result<CrawlOutcome>,Vec<String>,Vec<(String,Value)>) {
        let mut seen = Vec::new();
        let mut events = Vec::new();
        let outcome = crawl(&[web("/")],CrawlOptions { checkpoint,scope_sha256:None,queue_limit:limit },|_|true,
            |kind,data| { events.push((kind.to_owned(),data)); Ok(()) },
            |url| {
                assert_eq!(url.origin(),web("/").as_url().origin());
                let path = match url.query() { Some(query) => format!("{}?{query}",url.path()),None => url.path().to_owned() };
                seen.push(path.clone());
                Ok(match routes.get(&path) { Some((status,mime,body)) => response(*status,mime,body),None => response(404,"text/plain","") })
            });
        (outcome,seen,events)
    }
    fn checkpoint(pending: &[&str], visited: &[&str]) -> CrawlCheckpoint {
        CrawlCheckpoint { v:1,pending:pending.iter().map(|path|queue_entry(web(path),1,QueueKind::Navigation)).collect(),
            visited:visited.iter().map(|path|web(path)).collect(),omitted:0,scope_sha256:None }
    }

    #[test]
    fn passive_parsers_preserve_sources_and_reject_suffix_tricks_and_malformed_records() {
        let mut parsed = parse_subdomains(br#"{"host":"A.Example.com.\nb.example.com","input":"example.com","source":"cert"}
{"host":"a.example.com","sources":["crtsh","wayback"]}
{"host":"badexample.com"}
{"host":"other.example.com","input":"other.test"}
not json
"#,&domain()).unwrap();
        assert_eq!(parsed.items.iter().map(String::as_str).collect::<Vec<_>>(),["a.example.com","b.example.com"]);
        assert_eq!(parsed.observations["accepted"][0]["sources"],json!(["cert","crtsh","wayback"]));
        assert_eq!(parsed.observations["discarded"].as_array().unwrap().len(),3);
        assert_eq!(filter_passive(&mut parsed,|host|host != "b.example.com",false),1);
        assert_eq!(parsed.items,BTreeSet::from(["a.example.com".into()]));
        assert_eq!(parsed.observations["authorization_not_inferred_from_discovery"],true);
        assert!(parse_subdomains(&[0xff],&domain()).is_err());
        for value in ["example.com;id","$(id).example.com","-d","example.com\n--all","*.example.com"] {
            assert!(Domain::parse(value).is_err());
        }
    }

    #[test]
    fn archives_preserve_percent_encoding_query_order_and_historical_label() {
        let mut parsed = parse_urls(b"https://EXAMPLE.com/a%2Fb?q=%2F&x=1&x=2#fragment\nhttps://example.com/a%2Fb?q=%2F&x=1&x=2\nhttp://a.example.com:8080/\nhttps://badexample.com/\nhttps://user:pass@example.com/\nftp://example.com/\n",&domain()).unwrap();
        assert_eq!(parsed.items.len(),2);
        assert!(parsed.items.contains("https://example.com/a%2Fb?q=%2F&x=1&x=2"));
        assert_eq!(parsed.observations["asserted_live"],false);
        assert_eq!(parsed.observations["duplicates"],1);
        assert_eq!(filter_passive(&mut parsed,|host|host == "example.com",true),1);
        assert_eq!(parsed.items.len(),1);
        assert!(parse_urls(&[0xff],&domain()).is_err());
    }

    fn interrupted(stdout: &[u8]) -> Capture {
        Capture { pid:0,stdout:stdout.to_vec(),stderr:b"backend stopped\n".to_vec(),status:Some(ExitStatus::from_raw(7 << 8)),
            timed_out:false,output_overflow:false,errors:Vec::new(),descendant_statuses:Vec::new() }
    }
    #[test]
    fn interrupted_capture_parses_only_newline_complete_prefix_and_keeps_raw_tail() {
        let full = b"{\"host\":\"a.example.com\"}\n{\"host\":\"cut.example";
        let capture = interrupted(full);
        assert_eq!(STANDARD.decode(capture.evidence()["stdout_base64"].as_str().unwrap()).unwrap(),full);
        let output = captured_output(Backend::Subfinder,capture).unwrap();
        assert_eq!(output.stdout,b"{\"host\":\"a.example.com\"}\n");
        let partial = output.partial.as_ref().unwrap();
        assert_eq!(partial.backend_exit,Some(7));
        assert_eq!(partial.parsed_bytes,output.stdout.len());
        assert_eq!(partial.discarded_tail_bytes,full.len()-output.stdout.len());
        assert_eq!(partial.captured_bytes,full.len()+b"backend stopped\n".len());
        let parsed = parse_subdomains(&output.stdout,&domain()).unwrap();
        require_partial_items(&parsed,&output.partial).unwrap();
        assert_eq!(parsed.items,BTreeSet::from(["a.example.com".into()]));
    }
    #[test]
    fn interrupted_zero_usable_output_remains_failure() {
        for stdout in [b"".as_slice(),b" \n\t",b"{\"host\":\"a.example.com\"}"] {
            assert!(captured_output(Backend::Subfinder,interrupted(stdout)).is_err());
        }
        for stdout in [b"malformed\n".as_slice(),b"{\"host\":\"outside.test\"}\n"] {
            let output = captured_output(Backend::Subfinder,interrupted(stdout)).unwrap();
            let parsed = parse_subdomains(&output.stdout,&domain()).unwrap();
            assert!(require_partial_items(&parsed,&output.partial).is_err());
        }
    }
    #[test]
    fn successful_backend_can_return_a_complete_final_line_without_newline() {
        let mut capture = interrupted(b"https://example.com/no-newline");
        capture.status = Some(ExitStatus::from_raw(0));
        let output = captured_output(Backend::Gau(ArchiveProvider::Wayback),capture).unwrap();
        assert!(output.partial.is_none());
        assert_eq!(parse_urls(&output.stdout,&domain()).unwrap().items.len(),1);
    }
    #[test]
    fn dnsx_arguments_are_fixed_low_rate_and_include_explicit_negative_statuses() {
        let args = Backend::Dnsx.args(None,None).into_iter().map(|arg|arg.into_string().unwrap()).collect::<Vec<_>>();
        for flag in ["-silent","-json","-a","-aaaa","-cname","-duc"] { assert!(args.iter().any(|arg|arg == flag)); }
        assert!(args.windows(2).any(|pair|pair == ["-rcode","noerror,nxdomain,servfail,refused"]));
        assert!(args.windows(2).any(|pair|pair == ["-rl","2"]));
        assert!(!args.iter().any(|arg|arg == "-update" || arg == "-l"));
    }

    fn fixture(name: &str, input: &[u8], timeout: Duration, budget: usize) -> Capture {
        let executable = std::env::current_exe().unwrap();
        let args = ["--exact",name,"--ignored","--nocapture","--test-threads=1"].map(OsString::from);
        capture_command(&executable,&args,input,timeout,budget).unwrap()
    }
    fn assert_reaped(capture: &Capture) {
        assert_eq!(unsafe { libc::waitpid(capture.pid as i32,std::ptr::null_mut(),libc::WNOHANG) },-1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(),Some(libc::ECHILD));
    }
    #[test]
    fn runner_closes_stdin_and_preserves_binary_captures() {
        let capture = fixture("implementation::tests::fixture_success",&[],Duration::from_secs(3),65536);
        assert!(capture.succeeded(),"{:?}",capture.evidence());
        assert!(capture.stdout.ends_with(b"binary\0\xff\n"));
        assert_eq!(capture.stderr,b"stderr\0\xfe\n");
        assert_reaped(&capture);
    }
    #[test]
    fn runner_feeds_host_lines_and_closes_stdin_under_supervision() {
        let input = b"a.example.com\nb.example.com\n";
        let capture = fixture("implementation::tests::fixture_stdin",input,Duration::from_secs(3),65536);
        assert!(capture.succeeded(),"{:?}",capture.evidence());
        assert_eq!(capture.stderr,input);
        assert_reaped(&capture);
    }
    #[test]
    fn runner_nonzero_is_failure_not_empty_success() {
        let capture = fixture("implementation::tests::fixture_nonzero",&[],Duration::from_secs(3),65536);
        assert!(!capture.succeeded());
        assert_eq!(capture.status.unwrap().code(),Some(7));
        assert_eq!(capture.stderr,b"backend failed\n");
        assert_reaped(&capture);
    }
    #[test]
    fn runner_deadline_kills_and_reaps_the_entire_process_group() {
        let start = Instant::now();
        let capture = fixture("implementation::tests::fixture_hanging_group",&[],Duration::from_secs(1),65536);
        assert!(capture.timed_out);
        assert_eq!(capture.status.unwrap().signal(),Some(libc::SIGKILL));
        assert!(start.elapsed() < Duration::from_secs(3));
        assert_reaped(&capture);
        let text = String::from_utf8_lossy(&capture.stdout);
        let pid: i32 = text.split("GRANDCHILD=").nth(1).unwrap().split_whitespace().next().unwrap().parse().unwrap();
        assert!(capture.descendant_statuses.iter().any(|status|status["pid"] == pid && status["raw_wait_status"] == libc::SIGKILL));
        assert!(std::fs::metadata(format!("/proc/{pid}")).is_err());
    }
    #[test]
    fn runner_stdout_and_stderr_share_one_hard_budget_and_are_reaped() {
        let capture = fixture("implementation::tests::fixture_flood",&[],Duration::from_secs(3),4096);
        assert!(capture.output_overflow);
        assert!(!capture.timed_out);
        assert_eq!(capture.stdout.len()+capture.stderr.len(),4096);
        assert!(!capture.stderr.is_empty());
        assert!(!capture.stdout.is_empty());
        assert_eq!(capture.evidence()["discarded_bytes_at_least"],1);
        assert_reaped(&capture);
    }
    #[test]
    fn missing_backend_is_not_an_empty_capture() {
        assert!(capture_command(Path::new("/nonexistent-recon-backend"),&[],&[],Duration::from_secs(1),1024).is_err());
    }
    #[test]
    #[ignore = "isolated child process fixture, launched by runner test"]
    fn fixture_success() {
        let mut input = Vec::new();
        std::io::stdin().read_to_end(&mut input).unwrap();
        assert!(input.is_empty());
        std::io::stdout().write_all(b"binary\0\xff\n").unwrap();
        std::io::stdout().flush().unwrap();
        std::io::stderr().write_all(b"stderr\0\xfe\n").unwrap();
        std::process::exit(0);
    }
    #[test]
    #[ignore = "isolated child process fixture, launched by runner test"]
    fn fixture_stdin() {
        let mut input = Vec::new();
        std::io::stdin().read_to_end(&mut input).unwrap();
        std::io::stderr().write_all(&input).unwrap();
        std::process::exit(0);
    }
    #[test]
    #[ignore = "isolated child process fixture, launched by runner test"]
    fn fixture_nonzero() {
        std::io::stderr().write_all(b"backend failed\n").unwrap();
        std::process::exit(7);
    }
    #[test]
    #[ignore = "isolated child process fixture, launched by runner test"]
    fn fixture_hanging_group() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 { loop { unsafe { libc::pause(); } } }
        println!("GRANDCHILD={pid}");
        std::io::stdout().flush().unwrap();
        loop { std::thread::sleep(Duration::from_secs(1)); }
    }
    #[test]
    #[ignore = "isolated child process fixture, launched by runner test"]
    fn fixture_flood() {
        // Bounded stdout cannot consume the budget alone, regardless of scheduling.
        std::io::stdout().write_all(&[b'o';1024]).unwrap();
        std::io::stdout().flush().unwrap();
        loop { std::io::stderr().write_all(&[b'e';1024]).unwrap(); }
    }

    #[test]
    fn navigation_budget_is_not_starved_by_js_css_or_literal_candidates() {
        let mut root: String = (0..40).map(|i|format!("<script src='/bundle{i}.js'></script>")).collect();
        root.extend((0..80).map(|i|format!("<a href='/style{i}.css'>css</a>")));
        root.extend((0..50).map(|i|format!("<a href='/page{i}'>page</a>")));
        let mut inventory = routes(&[("/",200,"text/html",&root)]);
        for i in 0..40 { inventory.insert(format!("/bundle{i}.js"),(200,"application/javascript".into(),"const p='/literal-route';const t=`/api/${id}`;const n='/';".into())); }
        let (outcome,seen,_) = harness(None,512,inventory);
        let outcome = outcome.unwrap();
        assert_eq!(outcome.coverage["navigation_metadata_requests"],32);
        assert_eq!(outcome.coverage["js_asset_requests"],8);
        assert_eq!(seen.iter().filter(|path|path.starts_with("/page")).count(),29);
        assert!(!seen.iter().any(|path|path.ends_with(".css") || path == "/literal-route" || path.contains("${")));
        assert!(outcome.items.contains(web("/literal-route").as_str()));
        assert!(!outcome.checkpoint.pending.is_empty());
        assert!(outcome.partial.is_none());
    }
    #[test]
    fn templates_and_noise_remain_provenanced_candidates_not_fetch_targets() {
        let root = r#"<a href="/api/{id}">template</a><a href="/api/:name">named</a><script>let t=`/api/${id}`;let n='/';let p='/concrete';</script>"#;
        let (outcome,seen,events) = harness(None,512,routes(&[("/",200,"text/html",root)]));
        outcome.unwrap();
        assert_eq!(seen,["/robots.txt","/","/sitemap.xml"]);
        let discoveries: Vec<_> = events.iter().filter(|(kind,_)|kind == "crawl_link_discovery").flat_map(|(_,value)|value["discovered"].as_array().unwrap()).collect();
        assert!(discoveries.iter().any(|row|row["class"] == "template_candidate" && row["source"] == "inline_script_literal"));
        assert!(discoveries.iter().any(|row|row["class"] == "literal_noise"));
        assert!(discoveries.iter().all(|row|row["queue_status"] == "candidate_only"));
    }
    #[test]
    fn robots_rules_are_exclusions_not_links_and_longest_allow_wins() {
        let root = "<a href='/private'>private</a><a href='/private/open'>allow</a><a href='/secret.json'>blocked</a><a href='/public'>public</a>";
        let robots = "User-agent: *\nDisallow: /private\nAllow: /private/open\nDisallow: /*.json$\nSitemap: /extra.xml\nUser-agent: unrelated\nDisallow: /\n";
        let (outcome,seen,_) = harness(None,512,routes(&[("/",200,"text/html",root),("/robots.txt",200,"text/plain",robots),
            ("/extra.xml",200,"application/xml","<urlset><loc>/private/mapped</loc></urlset>")]));
        let outcome = outcome.unwrap();
        assert_eq!(seen[0],"/robots.txt");
        assert!(seen.iter().any(|path|path == "/private/open"));
        assert!(seen.iter().any(|path|path == "/extra.xml"));
        assert!(!seen.iter().any(|path|path == "/private" || path == "/private/mapped" || path == "/secret.json"));
        assert!(outcome.coverage["robots_excluded"].as_u64().unwrap() >= 3);
    }
    #[test]
    fn exact_origin_no_forms_and_no_automatic_redirects() {
        let root = r#"<a href="http://example.com/x">scheme</a><a href="//example.com:444/x">port</a><a href="https://evil.test/x">offsite</a><a href="https://badexample.com/x">suffix</a><a href="/redirect">redirect</a><form action="/submit"><input></form>"#;
        let (outcome,seen,events) = harness(None,512,routes(&[("/",200,"text/html",root),("/redirect",302,"text/html","<a href='/not-followed'>x</a>")]));
        outcome.unwrap();
        assert_eq!(seen,["/robots.txt","/","/sitemap.xml","/redirect"]);
        assert!(events.iter().any(|(kind,_)|kind == "crawl_redirect_not_followed"));
        let base = Url::parse("https://example.com/dir/").unwrap();
        for candidate in ["https://user:pass@example.com/","https://example.com.evil.test/","https://example.com:444/","javascript:alert(1)","#fragment"] {
            assert!(scoped_link(&base,candidate,&base.origin()).is_err());
        }
    }
    #[test]
    fn external_html_base_does_not_escape_exact_origin() {
        let (outcome,seen,_) = harness(None,512,routes(&[("/",200,"text/html","<base href='https://evil.test/'><a href='relative'>x</a><a href='/absolute'>x</a>")]));
        outcome.unwrap();
        assert_eq!(seen,["/robots.txt","/","/sitemap.xml"]);
    }
    #[test]
    fn checkpoint_resumes_pending_before_discovery_and_skips_visited_content() {
        let saved = checkpoint(&["/queued","/done"],&["/","/robots.txt","/sitemap.xml","/done"]);
        let (outcome,seen,events) = harness(Some(&saved),512,routes(&[("/queued",200,"text/html","<a href='/new'>new</a><a href='/done'>old</a>")]));
        let outcome = outcome.unwrap();
        assert_eq!(seen,["/robots.txt","/queued","/new"]);
        assert!(outcome.checkpoint.pending.is_empty());
        assert!(events.iter().any(|(kind,data)|kind == "crawl_safety_preflight" && data["resume_visited_exception"] == true));
        assert_eq!(outcome.coverage["robots_revalidated_on_resume"],true);
    }
    #[test]
    fn checkpoint_scope_mismatch_fails_before_fetch_or_discovery() {
        let mut saved = checkpoint(&["/queued"],&[]);
        saved.scope_sha256 = Some("a".repeat(64));
        let (outcome,seen,events) = harness(Some(&saved),512,Routes::new());
        assert!(outcome.is_err());
        assert!(seen.is_empty());
        assert!(events.is_empty());
        saved.scope_sha256 = None;
        saved.pending[0].url = WebUrl::parse("https://other.test/x").unwrap();
        let (outcome,seen,_) = harness(Some(&saved),512,Routes::new());
        assert!(outcome.is_err());
        assert!(seen.is_empty());
    }
    #[test]
    fn queue_budget_preserves_navigation_and_discloses_every_dropped_entry() {
        let mut root: String = (0..20).map(|i|format!("<script src='/bundle{i}.js'></script>")).collect();
        root.extend((0..10).map(|i|format!("<a href='/page{i}'>page</a>")));
        let (outcome,seen,_) = harness(None,4,routes(&[("/",200,"text/html",&root)]));
        let outcome = outcome.unwrap();
        assert!(seen.iter().any(|path|path.starts_with("/page")));
        assert!(!seen.iter().any(|path|path.ends_with(".js")));
        assert_eq!(outcome.checkpoint.omitted,27);
        assert!(outcome.checkpoint.pending.len() <= 4);
    }
    #[test]
    fn depth_limit_retains_discovery_without_fetching_a_third_level() {
        let (outcome,seen,_) = harness(None,512,routes(&[("/",200,"text/html","<a href='/one'>x</a>"),
            ("/one",200,"text/html","<a href='/two'>x</a>"),("/two",200,"text/html","<a href='/three'>x</a>")]));
        let outcome = outcome.unwrap();
        assert!(!seen.iter().any(|path|path == "/three"));
        assert!(outcome.items.contains(web("/three").as_str()));
        assert_eq!(outcome.coverage["depth_limited_links"],1);
    }
    #[test]
    fn operational_failures_are_partial_after_useful_work_and_errors_without_it() {
        let options = || CrawlOptions { checkpoint:None,scope_sha256:None,queue_limit:512 };
        let outcome = crawl(&[web("/")],options(),|_|true,|_,_|Ok(()),|url| {
            if url.path() == "/sitemap.xml" { Err(network::FetchError::Operational("timeout".into())) }
            else { Ok(response(200,"text/plain","")) }
        }).unwrap();
        assert!(outcome.partial.is_some());
        assert!(outcome.checkpoint.pending.iter().any(|entry|entry.url.as_url().path() == "/sitemap.xml"));
        assert!(crawl(&[web("/")],options(),|_|true,|_,_|Ok(()),|_|Err(network::FetchError::Operational("timeout".into()))).is_err());
        let negative = crawl(&[web("/")],options(),|_|true,|_,_|Ok(()),|_|Err(network::FetchError::Negative("connection refused".into()))).unwrap();
        assert!(negative.items.is_empty());
        assert!(negative.partial.is_none());
        assert_eq!(negative.coverage["explicit_negatives"],1);
    }
    #[test]
    fn response_body_transport_error_is_partial_not_a_complete_capped_body() {
        let outcome = crawl(&[web("/")],CrawlOptions { checkpoint:None,scope_sha256:None,queue_limit:512 },|_|true,|_,_|Ok(()),|url| {
            let mut fetched = response(200,"text/plain","captured prefix");
            if url.path() == "/" { fetched.truncated = true; fetched.read_error = Some("connection reset".into()); }
            Ok(fetched)
        }).unwrap();
        assert!(outcome.partial.is_some());
        assert!(outcome.checkpoint.pending.iter().any(|entry|entry.url.as_url().path() == "/"));
        assert!(!outcome.checkpoint.visited.iter().any(|url|url.as_url().path() == "/"));
    }
    #[test]
    fn audit_and_configuration_failures_are_never_swallowed() {
        for error in [network::FetchError::Audit("capture rejected".into()),network::FetchError::Invalid("bad headers".into())] {
            let mut pending = Some(error);
            let mut attempts = 0;
            assert!(crawl(&[web("/")],CrawlOptions { checkpoint:None,scope_sha256:None,queue_limit:512 },|_|true,|_,_|Ok(()),|_| {
                attempts += 1;
                Err(pending.take().unwrap())
            }).is_err());
            assert_eq!(attempts,1);
        }
    }
    #[test]
    fn failed_required_archive_preserves_completed_crawl_but_not_evidence_failures() {
        let mut result = WorkflowResult::complete(Vec::new());
        let mut items = BTreeSet::from([web("/useful").as_str().to_owned()]);
        merge_archive(&mut result,&mut items,1,Err(BackendFailure::Operational("gau unavailable".into())),|_,_|Ok(())).unwrap();
        assert!(items.contains(web("/useful").as_str()));
        assert!(result.partial.is_some());
        assert_eq!(result.coverage["archive"]["required_stage_failed"],true);
        assert!(merge_archive(&mut result,&mut items,1,Err(BackendFailure::Evidence("capture rejected".into())),|_,_|Ok(())).is_err());
        assert!(merge_archive(&mut result,&mut items,1,Err(BackendFailure::Operational("gau failed".into())),|_,_|Err("journal write failed".into())).is_err());
        assert!(merge_archive(&mut result,&mut items,0,Err(BackendFailure::Operational("gau failed".into())),|_,_|Ok(())).is_err());
    }

    #[test]
    fn visited_checkpoint_budget_is_bounded_without_forgetting_completed_content() {
        let mut saved = checkpoint(&["/queued"],&["/","/robots.txt","/sitemap.xml"]);
        saved.visited.extend((0..4093).map(|index|web(&format!("/visited{index}"))));
        let (outcome,seen,_) = harness(Some(&saved),1,Routes::new());
        let outcome = outcome.unwrap();
        assert_eq!(seen,["/robots.txt"]);
        assert_eq!(outcome.checkpoint.visited.len(),4096);
        assert_eq!(outcome.checkpoint.pending.len(),1);
        assert_eq!(outcome.checkpoint.pending[0].url.as_url().path(),"/queued");
        assert_eq!(outcome.coverage["visited_budget_exhausted"],true);
    }

    #[test]
    fn resumed_template_and_static_entries_are_not_automatically_fetched() {
        let saved = checkpoint(&["/api/{id}.js","/styles.css"],&["/","/robots.txt","/sitemap.xml"]);
        let (outcome,seen,events) = harness(Some(&saved),512,Routes::new());
        let outcome = outcome.unwrap();
        assert_eq!(seen,["/robots.txt"]);
        assert!(outcome.checkpoint.pending.is_empty());
        assert!(events.iter().any(|(kind,data)|kind == "crawl_not_queried" && data["reason"] == "template_candidate"));
    }

    #[test]
    fn unavailable_robots_preserves_pending_without_probing_the_application() {
        let (outcome,seen,_) = harness(None,512,routes(&[("/robots.txt",503,"text/plain","unavailable")]));
        let outcome = outcome.unwrap();
        assert_eq!(seen,["/robots.txt"]);
        assert!(outcome.partial.is_some());
        assert_eq!(outcome.checkpoint.pending.len(),2);
        assert_eq!(outcome.coverage["robots_safety_unavailable"],1);
        assert_eq!(outcome.coverage["failed_fetches"],0);
    }

    #[test]
    fn same_origin_html_base_resolves_relative_navigation_and_entities() {
        let (outcome,seen,_) = harness(None,512,routes(&[("/",200,"text/html","<base href='/assets/'><a href='account?a=1&amp;b=%2F'>x</a>")]));
        let outcome = outcome.unwrap();
        assert!(seen.iter().any(|path|path == "/assets/account?a=1&b=%2F"));
        assert!(outcome.items.contains(web("/assets/account?a=1&b=%2F").as_str()));
        assert!(!seen.iter().any(|path|path == "/account?a=1&b=%2F"));
    }

    #[test]
    fn empty_robots_directive_does_not_merge_an_unrelated_agent_group() {
        let rules = Robots::parse(b"User-agent: *\nDisallow:\nUser-agent: unrelated\nDisallow: /\n");
        assert!(rules.permits(web("/application").as_url()));
    }

    fn completed_archive(provider: ArchiveProvider, stdout: &[u8], stderr: &[u8]) -> CommandOutput {
        let mut capture = interrupted(stdout);
        capture.status = Some(ExitStatus::from_raw(0));
        capture.stderr = stderr.to_vec();
        captured_output(Backend::Gau(provider), capture).unwrap()
    }

    #[test]
    fn one_provider_timeout_does_not_erase_the_other_sources_urls_or_capture_facts() {
        let mut capture = interrupted(b"");
        capture.timed_out = true;
        capture.status = Some(ExitStatus::from_raw(libc::SIGKILL));
        let captured_bytes = capture.stderr.len();
        let failed = captured_output(Backend::Gau(ArchiveProvider::Wayback),capture).map_err(BackendFailure::Interrupted);
        let completed = completed_archive(ArchiveProvider::CommonCrawl,b"https://example.com/from-commoncrawl\n",b"");
        let outcome = collect_archives(&domain(), |_|true,
            [(ArchiveProvider::Wayback,failed),(ArchiveProvider::CommonCrawl,Ok(completed))], |_,_|Ok(())).unwrap();
        assert_eq!(outcome.items,BTreeSet::from(["https://example.com/from-commoncrawl".into()]));
        assert_eq!(outcome.partial_provider,Some("wayback"));
        let partial = outcome.partial.as_ref().unwrap();
        assert_eq!(partial.captured_bytes,captured_bytes);
        assert_eq!(partial.parsed_bytes,0);
        assert_eq!(partial.backend_signal,Some(libc::SIGKILL));
        assert_eq!(partial.cutoff_reason,"timeout");
        let mut result = WorkflowResult::complete(Vec::new());
        let mut items = BTreeSet::new();
        merge_archive(&mut result,&mut items,0,Ok(outcome),|_,_|Ok(())).unwrap();
        assert!(result.partial.is_some());
        assert_eq!(items,BTreeSet::from(["https://example.com/from-commoncrawl".into()]));
        assert_eq!(result.coverage["archive"]["completed"],false);
        assert_eq!(result.coverage["archive"]["providers"][0]["completed"],false);
        assert_eq!(result.coverage["archive"]["providers"][1]["completed"],true);
    }

    #[test]
    fn provider_reported_errors_with_zero_exit_are_not_successful_empty_archives() {
        for (provider, diagnostic) in [
            (ArchiveProvider::Wayback,b"level=warning msg=\"example.com - timeout\" provider=wayback\n".as_slice()),
            (ArchiveProvider::CommonCrawl,b"level=warning msg=\"error instantiating commoncrawl: API unavailable\"\n".as_slice())
        ] {
            let mut capture = interrupted(b"");
            capture.status = Some(ExitStatus::from_raw(0));
            capture.stderr = diagnostic.to_vec();
            let partial = captured_output(Backend::Gau(provider),capture).err().unwrap();
            assert_eq!(partial.backend_exit,Some(0));
            assert_eq!(partial.cutoff_reason,"provider_reported_error");
            assert_eq!(partial.captured_bytes,diagnostic.len());
        }
        let mut capture = interrupted(b"");
        capture.status = Some(ExitStatus::from_raw(0));
        capture.stderr = b"level=warning msg=\"error reading config: Config file missing, using default config\"\n".to_vec();
        let partial = captured_output(Backend::Gau(ArchiveProvider::Wayback),capture).err().unwrap();
        assert_eq!(partial.cutoff_reason,"backend_configuration_error");
        assert_eq!(partial.backend_exit,Some(0));
        let output = completed_archive(ArchiveProvider::Wayback,b"https://example.com/kept\n",
            b"level=info msg=\"fetching example.com\" page=0 provider=wayback\n");
        assert_eq!(output.stdout,b"https://example.com/kept\n");
        assert!(output.partial.is_none());
    }

    #[test]
    fn provider_error_retains_complete_url_lines_but_never_the_unfinished_tail() {
        let stdout = b"https://example.com/kept\nhttps://example.com/cut";
        let mut capture = interrupted(stdout);
        capture.status = Some(ExitStatus::from_raw(0));
        capture.stderr = b"level=warning msg=\"example.com - timeout\" provider=wayback\n".to_vec();
        let output = captured_output(Backend::Gau(ArchiveProvider::Wayback),capture).unwrap();
        assert_eq!(output.stdout,b"https://example.com/kept\n");
        assert_eq!(output.partial.as_ref().unwrap().discarded_tail_bytes,b"https://example.com/cut".len());
        let outcome = collect_archives(&domain(), |_|true,
            [(ArchiveProvider::Wayback,Ok(output))], |_,_|Ok(())).unwrap();
        assert_eq!(outcome.items,BTreeSet::from(["https://example.com/kept".into()]));
        assert!(outcome.partial.is_some());
    }

    #[test]
    fn unavailable_provider_plus_empty_provider_is_failure_not_a_negative_result() {
        let empty = completed_archive(ArchiveProvider::CommonCrawl,b"",b"");
        let outcome = collect_archives(&domain(), |_|true,
            [(ArchiveProvider::Wayback,Err(BackendFailure::Operational("backend unavailable".into()))),
             (ArchiveProvider::CommonCrawl,Ok(empty))], |_,_|Ok(())).unwrap();
        let mut result = WorkflowResult::complete(Vec::new());
        assert!(merge_archive(&mut result,&mut BTreeSet::new(),0,Ok(outcome),|_,_|Ok(())).is_err());
        let empty = ArchiveProvider::ALL.map(|provider|(provider,Ok(completed_archive(provider,b"",b""))));
        let outcome = collect_archives(&domain(), |_|true, empty, |_,_|Ok(())).unwrap();
        let mut result = WorkflowResult::complete(Vec::new());
        let mut items = BTreeSet::new();
        merge_archive(&mut result,&mut items,0,Ok(outcome),|_,_|Ok(())).unwrap();
        assert!(items.is_empty());
        assert!(result.partial.is_none());
        assert_eq!(result.coverage["archive"]["completed"],true);
    }

    #[test]
    fn isolated_sources_deduplicate_and_apply_policy_without_inventing_provenance() {
        let stages = [
            (ArchiveProvider::Wayback,Ok(completed_archive(ArchiveProvider::Wayback,
                b"https://example.com/shared\nhttps://excluded.example.com/private\n",b""))),
            (ArchiveProvider::CommonCrawl,Ok(completed_archive(ArchiveProvider::CommonCrawl,
                b"https://example.com/shared\nhttps://example.com/other\n",b"")))
        ];
        let mut sources = Vec::new();
        let outcome = collect_archives(&domain(), |host|host != "excluded.example.com", stages,
            |kind,data| { if kind == "archive_url_discovery" { sources.push(data["providers"].clone()); } Ok(()) }).unwrap();
        assert_eq!(outcome.items,BTreeSet::from(["https://example.com/shared".into(),"https://example.com/other".into()]));
        assert_eq!(outcome.excluded,1);
        assert_eq!(sources,vec![json!(["wayback"]),json!(["commoncrawl"])]);
        assert!(outcome.partial.is_none());
    }

    #[test]
    fn invalid_provider_output_preserves_the_other_source_but_journal_failures_abort() {
        let stages = [
            (ArchiveProvider::Wayback,Ok(completed_archive(ArchiveProvider::Wayback,b"\xff\n",b""))),
            (ArchiveProvider::CommonCrawl,Ok(completed_archive(ArchiveProvider::CommonCrawl,b"https://example.com/kept\n",b"")))
        ];
        let outcome = collect_archives(&domain(), |_|true, stages, |_,_|Ok(())).unwrap();
        assert_eq!(outcome.items,BTreeSet::from(["https://example.com/kept".into()]));
        assert_eq!(outcome.partial.as_ref().unwrap().cutoff_reason,"invalid_archive_output");
        assert_eq!(outcome.partial.as_ref().unwrap().captured_bytes,2);
        let stage = [(ArchiveProvider::Wayback,Ok(completed_archive(ArchiveProvider::Wayback,b"https://example.com/kept\n",b"")))];
        assert!(matches!(collect_archives(&domain(), |_|true, stage, |_,_|Err("journal unavailable".into())),
            Err(BackendFailure::Evidence(_))));
    }

    #[test]
    fn managed_gau_configuration_is_private_and_cleaned_without_clobbering_files() {
        let path;
        {
            let config = GauConfig::new().unwrap();
            path = config.path.clone();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            assert!(metadata.file_type().is_file());
            assert_eq!(metadata.permissions().mode() & 0o777,0o600);
            let original = std::fs::read(&path).unwrap();
            assert!(GauConfig::create_in(&path).is_err());
            assert_eq!(std::fs::read(&path).unwrap(),original);
            assert!(path.exists());
        }
        assert!(!path.exists());
    }
}
}
