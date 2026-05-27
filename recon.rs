use std::env;
use std::fs;
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::{Command, Stdio};

const RED: &str = "\x1b[1;31m";
const RESET: &str = "\x1b[0m";

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

    // ── Directory setup ──────────────────────────────────────────────────────
    let base = Path::new(domain);
    let subdomain_path = base.join("subdomains");

    for dir in [base, &subdomain_path] {
        ensure_dir(dir);
    }

    let found_txt = subdomain_path.join("found.txt");
    let alive_txt = subdomain_path.join("alive.txt");
    let web_technology_txt = subdomain_path.join("web_technology.txt"); // Fix 1: no dots in variable names

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
    for line in httprobe_out.stdout.lines().map_while(Result::ok) {
        if line.starts_with("https") {
            let host = line
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            println!("{}", host);
            writeln!(alive_file, "{}", host).expect("Failed to write to alive.txt");
        }
    }

    let alive_txt_str = alive_txt.to_string_lossy().into_owned();

    // ── whatweb ──────────────────────────────────────────────────────────────
    banner("Running whatweb . . .");
    run_to_file(
        "whatweb",
        &["-i", &alive_txt_str, "-a", "3", "-v"],
        &web_technology_txt,
    );

    // ── nuclei ───────────────────────────────────────────────────────────────
    banner("Running nuclei against URLs . . .");
    run_live("nuclei", &["-l", &alive_txt_str]);

    // ── rustscan ─────────────────────────────────────────────────────────────
    banner("Running rustscan on alive subdomains . . .");    
    run_live(
    "rustscan",
    &["-a", &alive_txt_str, "-r", "1-65535", "--ulimit", "5000", "--", "-sC", "-sV"],
    );
}
