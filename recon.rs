use std::env;
use std::fs;
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::{Command, Stdio};
 
const RED: &str = "\x1b[1;31m";
const RESET: &str = "\x1b[0m";

fn print_banner() {
    println!("{RED}", RED = RED);
    println!(r"                                                                      ");
    println!(r"  ┌────────────────────────────────────────────────────────────┐     ");
    println!(r"  │   (ง •̀_•́)ง   Hunt. Enumerate. Pwn.                         │     ");
    println!(r"  │       ~ Automated Recon Framework ~                        │     ");
    println!(r"  │   ⚔  subfinder • assetfinder • httprobe • nuclei           │     ");
    println!(r"  │   ⚔  whatweb   • rustscan    • feroxbuster                 │     ");
    println!(r"  └────────────────────────────────────────────────────────────┘     ");
    println!("{RESET}", RESET = RESET);
    println!();
    }

fn banner(msg: &str) {
    println!("{RED}[+] {msg}{RESET}");
}
 
fn ensure_dir(path: &Path) {
    if !path.exists() {
        fs::create_dir_all(path)
            .unwrap_or_else(|e| panic!("Failed to create directory {:?}: {}", path, e));
    }
}
 
/// Run a command, wait for it to finish, return stdout bytes.
/// Inherits stderr so the tool's own output/errors print live to the terminal.
fn run_capture(cmd: &str, args: &[&str]) -> Vec<u8> {
    let output = Command::new(cmd)
        .args(args)
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|e| panic!("Failed to run '{}': {}", cmd, e));
    output.stdout
}
 
/// Run a command whose output streams live to the terminal (nothing captured).
fn run_live(cmd: &str, args: &[&str]) {
    Command::new(cmd)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("Failed to run '{}': {}", cmd, e));
}
 
/// Run a command and capture its stdout into a file.
fn run_to_file(cmd: &str, args: &[&str], out_path: &Path) {
    let output = Command::new(cmd)
        .args(args)
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|e| panic!("Failed to run '{}': {}", cmd, e));
    fs::write(out_path, &output.stdout)
        .unwrap_or_else(|e| panic!("Failed to write output of '{}' to {:?}: {}", cmd, out_path, e));
}
 
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <domain>", args[0]);
        std::process::exit(1);
    }
    let domain = &args[1];
    print_banner();
 
    // ── Directory setup ──────────────────────────────────────────────────────
    let base = Path::new(domain);
    let subdomain_path = base.join("subdomains");
 
    for dir in [base, &subdomain_path] {
        ensure_dir(dir);
    }
 
    let found_txt = subdomain_path.join("found.txt");
    let alive_txt = subdomain_path.join("alive.txt");
    let web_technology_txt = subdomain_path.join("web_technology.txt");
 
    // ── subfinder ────────────────────────────────────────────────────────────
    banner("Launching subfinder . . .");
    let subfinder_out = run_capture("subfinder", &["-d", domain, "-all"]);
    fs::write(&found_txt, &subfinder_out).expect("Failed to write subfinder output");
 
    // ── assetfinder ──────────────────────────────────────────────────────────
    banner("Launching assetfinder . . .");
    let assetfinder_out = run_capture("assetfinder", &[domain]);
 
    // Append only lines that contain the target domain (mirrors: | grep $domain)
    let mut found_file = fs::OpenOptions::new()
        .append(true)
        .open(&found_txt)
        .expect("Failed to open found.txt for appending");
 
    for line in assetfinder_out.lines().map_while(Result::ok) {
        if line.contains(domain.as_str()) {
            writeln!(found_file, "{}", line).expect("Failed to write to found.txt");
        }
    }
 
    // ── httprobe: find alive subdomains ──────────────────────────────────────
    banner("Finding alive subdomains . . .");
 
    // Read found.txt, filter by domain, sort + dedup (mirrors: grep | sort -u)
    let found_content = fs::read_to_string(&found_txt).expect("Failed to read found.txt");
    let mut candidates: Vec<String> = found_content
        .lines()
        .filter(|l| l.contains(domain.as_str()))
        .map(String::from)
        .collect();
    candidates.sort();
    candidates.dedup();
    let candidates_input = candidates.join("\n");
 
    // Pipe candidates into httprobe
    let mut httprobe = Command::new("httprobe")
        .arg("--prefer-https")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn httprobe");
 
    httprobe
        .stdin
        .take()
        .unwrap()
        .write_all(candidates_input.as_bytes())
        .expect("Failed to write to httprobe stdin");
 
    let httprobe_out = httprobe.wait_with_output().expect("httprobe failed");
 
    // Keep only https results, strip the scheme, write + print (mirrors: grep https | sed | tee)
    let mut alive_file = fs::File::create(&alive_txt).expect("Failed to create alive.txt");
    let httprobe_lines: Vec<String> = httprobe_out.stdout.lines().map_while(Result::ok).collect();
    println!("[*] httprobe returned {} result(s)", httprobe_lines.len());
    for line in &httprobe_lines {
        println!("    httprobe raw: {}", line);
        if line.starts_with("https://") || line.starts_with("http://") {
            let host = line
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            println!("[*] alive: {}", host);
            writeln!(alive_file, "{}", host).expect("Failed to write to alive.txt");
        }
    }
 
    // Read alive hosts once, reuse for whatweb, nuclei and rustscan
    let alive_content = fs::read_to_string(&alive_txt).expect("Failed to read alive.txt");
    let alive_hosts: Vec<&str> = alive_content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
 
    if alive_hosts.is_empty() {
        eprintln!("[!] No alive hosts found in alive.txt — skipping whatweb, nuclei and rustscan.");
        return;
    }
 
    println!("[*] {} alive host(s) found:", alive_hosts.len());
    for h in &alive_hosts {
        println!("    {}", h);
    }
 
    let alive_txt_str = alive_txt.to_string_lossy().into_owned();
 
    // ── whatweb ──────────────────────────────────────────────────────────────
    // alive.txt contains bare hostnames (scheme stripped after httprobe),
    // so restore https:// — whatweb requires full URLs as targets.
    banner("Running whatweb . . .");
    let whatweb_urls: Vec<String> = alive_hosts
        .iter()
        .map(|h| format!("https://{}", h))
        .collect();
    let mut whatweb_args: Vec<&str> = vec!["-a", "3", "-v", "--open-timeout", "30", "--read-timeout", "30"];
    whatweb_args.extend(whatweb_urls.iter().map(String::as_str));
    run_to_file("whatweb", &whatweb_args, &web_technology_txt);
 
    // ── nuclei ───────────────────────────────────────────────────────────────
    banner("Running nuclei against URLs . . .");
    run_live("nuclei", &["-l", &alive_txt_str]);

    // ── feroxbuster ───────────────────────────────────────────────────────────
    // For every alive host, run feroxbuster for directory discovery.
    // Results for each host are appended to <domain>/scans/directories.txt
    let scan_path = base.join("scans");
    ensure_dir(&scan_path);
 
    let wordlist = "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt";
    let directories_out = scan_path.join("directories.txt");
    let directories_out_str = directories_out.to_string_lossy().into_owned();
 
    for host in &alive_hosts {
        let url = format!("https://{}", host);
        banner(&format!("feroxbuster directory scan: {} . . .", host));
        run_live(
            "feroxbuster",
            &[
                "--url",          &url,
                "--wordlist",     wordlist,
                "--output",       &directories_out_str,
                "--append-output",
                "--threads",      "50",
                "--status-codes", "200,301,302,403",
                "--silent",
            ],
        );
    }
 

 
    // ── rustscan ─────────────────────────────────────────────────────────────
    // Pass hosts as a comma-separated list to avoid rustscan treating the
    // domain directory as a target.
    banner("Running rustscan on alive subdomains . . .");
    let hosts_csv = alive_hosts.join(",");
    run_live(
        "rustscan",
        &["-a", &hosts_csv, "-r", "1-65535", "--ulimit", "5000", "--", "-sC", "-sV"],
    );
}
