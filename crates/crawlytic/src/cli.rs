use crawlytic_core::{
    CrawlLimits, EXIT_USAGE, HeadlessReport, HeadlessRequest, Profile, ScheduleExec,
    ScheduleGuidance, SchedulePlan, Store, default_lock_path, run_audit,
};
use std::path::{Path, PathBuf};

const HELP: &str = "\
Crawlytic — self-hosted technical SEO auditor

Usage:
  crawlytic [profile.toml]     Interactive Ratatui UI
  crawlytic audit [options]    Noninteractive crawl + evaluate + CSV/JSON export
  crawlytic schedule print     Print systemd timer/service and crontab (does not install)
  crawlytic help

Audit options:
  --profile PATH       Crawl profile (required)
  --store PATH         SQLite store (default: CRAWLYTIC_STORE or ./crawlytic.sqlite)
  --export-dir PATH    Directory for CSV/JSON (default: current directory)
  --lock PATH          Overlap lock file (default: <store>.lock)
  --resume             Resume the latest incomplete/running run instead of starting
  --json               Machine-readable report on stdout (default)

Schedule print options:
  --profile PATH
  --store PATH
  --lock PATH
  --binary PATH
  --working-directory PATH
  --env-file PATH
  --json

Exit codes: 0 ok, 1 usage, 2 auth, 3 overlap, 4 crawl, 5 export.
Overlapping runs are prevented, not queued. Email stays disabled.
A schedule is not enabled until schedule_time and schedule_timezone are set.
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    Tui { selected: Option<String> },
    Audit(AuditArgs),
    SchedulePrint(ScheduleArgs),
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditArgs {
    pub profile: PathBuf,
    pub store: PathBuf,
    pub export_dir: PathBuf,
    pub lock: PathBuf,
    pub resume: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleArgs {
    pub profile: PathBuf,
    pub store: PathBuf,
    pub lock: PathBuf,
    pub binary: PathBuf,
    pub working_directory: PathBuf,
    pub env_file: PathBuf,
    pub json: bool,
}

pub fn parse_args(
    args: &[String],
    cwd: &Path,
    store_env: Option<&str>,
) -> Result<Invocation, String> {
    match args.first().map(String::as_str) {
        None => Ok(Invocation::Tui { selected: None }),
        Some("help" | "-h" | "--help") => Ok(Invocation::Help),
        Some("audit") => parse_audit(&args[1..], cwd, store_env).map(Invocation::Audit),
        Some("schedule") => match args.get(1).map(String::as_str) {
            Some("print") => {
                parse_schedule(&args[2..], cwd, store_env).map(Invocation::SchedulePrint)
            }
            Some(other) => Err(format!(
                "Unknown schedule subcommand {other}. Use: crawlytic schedule print"
            )),
            None => Err("Usage: crawlytic schedule print".into()),
        },
        Some(other) if other.starts_with('-') => Err(format!(
            "Unknown option {other}. Use crawlytic help. A profile path starts the TUI."
        )),
        Some(selected) => Ok(Invocation::Tui {
            selected: Some(selected.to_owned()),
        }),
    }
}

pub fn help_text() -> &'static str {
    HELP
}

fn parse_audit(args: &[String], cwd: &Path, store_env: Option<&str>) -> Result<AuditArgs, String> {
    let mut profile = None;
    let mut store = None;
    let mut export_dir = None;
    let mut lock = None;
    let mut resume = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--profile" => {
                profile = Some(required_value(args, &mut i, "--profile")?);
            }
            "--store" => store = Some(required_value(args, &mut i, "--store")?),
            "--export-dir" => export_dir = Some(required_value(args, &mut i, "--export-dir")?),
            "--lock" => lock = Some(required_value(args, &mut i, "--lock")?),
            "--resume" => {
                resume = true;
                i += 1;
            }
            "--json" => i += 1,
            other => return Err(format!("Unknown audit option {other}")),
        }
    }
    let profile = profile.ok_or_else(|| "audit requires --profile PATH".to_owned())?;
    let store = store.unwrap_or_else(|| default_store(cwd, store_env));
    let lock = lock.unwrap_or_else(|| default_lock_path(&store));
    Ok(AuditArgs {
        profile,
        store,
        export_dir: export_dir.unwrap_or_else(|| cwd.to_path_buf()),
        lock,
        resume,
    })
}

fn parse_schedule(
    args: &[String],
    cwd: &Path,
    store_env: Option<&str>,
) -> Result<ScheduleArgs, String> {
    let mut profile = None;
    let mut store = None;
    let mut lock = None;
    let mut binary = None;
    let mut working_directory = None;
    let mut env_file = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--profile" => profile = Some(required_value(args, &mut i, "--profile")?),
            "--store" => store = Some(required_value(args, &mut i, "--store")?),
            "--lock" => lock = Some(required_value(args, &mut i, "--lock")?),
            "--binary" => binary = Some(required_value(args, &mut i, "--binary")?),
            "--working-directory" => {
                working_directory = Some(required_value(args, &mut i, "--working-directory")?)
            }
            "--env-file" => env_file = Some(required_value(args, &mut i, "--env-file")?),
            "--json" => {
                json = true;
                i += 1;
            }
            other => return Err(format!("Unknown schedule option {other}")),
        }
    }
    let profile = profile.ok_or_else(|| "schedule print requires --profile PATH".to_owned())?;
    let store = store.unwrap_or_else(|| default_store(cwd, store_env));
    let lock = lock.unwrap_or_else(|| default_lock_path(&store));
    Ok(ScheduleArgs {
        profile,
        store,
        lock,
        binary: binary.unwrap_or_else(|| PathBuf::from("crawlytic")),
        working_directory: working_directory.unwrap_or_else(|| cwd.to_path_buf()),
        env_file: env_file.unwrap_or_else(|| cwd.join(".env")),
        json,
    })
}

fn required_value(args: &[String], i: &mut usize, flag: &str) -> Result<PathBuf, String> {
    let value = args
        .get(*i + 1)
        .ok_or_else(|| format!("{flag} requires a path"))?;
    *i += 2;
    Ok(PathBuf::from(value))
}

fn default_store(cwd: &Path, store_env: Option<&str>) -> PathBuf {
    store_env
        .map(PathBuf::from)
        .unwrap_or_else(|| cwd.join("crawlytic.sqlite"))
}

pub fn usage_report(message: impl Into<String>) -> HeadlessReport {
    HeadlessReport {
        ok: false,
        exit_code: EXIT_USAGE,
        kind: "usage".into(),
        run_id: None,
        status: None,
        csv_path: None,
        json_path: None,
        overlap: false,
        email: false,
        auth_resolved: false,
        message: message.into(),
    }
}

pub fn run_audit_command(args: AuditArgs) -> anyhow::Result<HeadlessReport> {
    let profile = load_profile(&args.profile)?;
    let store = Store::open(&args.store)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let _guard = runtime.enter();
    Ok(runtime.block_on(run_audit(HeadlessRequest {
        store,
        limits: CrawlLimits::from_profile(&profile),
        profile,
        export_dir: args.export_dir,
        lock_path: args.lock,
        resume: args.resume,
    })))
}

pub fn render_schedule(args: ScheduleArgs) -> anyhow::Result<String> {
    let profile = load_profile(&args.profile)?;
    let plan = SchedulePlan::from_profile(&profile)?;
    let guidance = ScheduleGuidance::render(
        plan,
        &ScheduleExec {
            working_directory: args.working_directory,
            binary: args.binary,
            profile: args.profile,
            store: args.store,
            lock: args.lock,
            env_file: args.env_file,
        },
    )?;
    if args.json {
        Ok(guidance.to_json()?)
    } else {
        Ok(format!(
            "# crawlytic-audit.service\n{}# crawlytic-audit.timer\n{}# crontab (MAILTO is empty; overlap refused by --lock)\n{}",
            guidance.systemd_service, guidance.systemd_timer, guidance.crontab
        ))
    }
}

fn load_profile(path: &Path) -> anyhow::Result<Profile> {
    let text = std::fs::read_to_string(path)?;
    Profile::load(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn tui_is_the_default_and_profile_path_is_not_a_subcommand() {
        let cwd = Path::new("/tmp");
        assert_eq!(
            parse_args(&[], cwd, None).unwrap(),
            Invocation::Tui { selected: None }
        );
        assert_eq!(
            parse_args(&args(&["profile.local.toml"]), cwd, None).unwrap(),
            Invocation::Tui {
                selected: Some("profile.local.toml".into())
            }
        );
        assert!(matches!(
            parse_args(&args(&["help"]), cwd, None).unwrap(),
            Invocation::Help
        ));
    }

    #[test]
    fn audit_requires_profile_and_defaults_lock_next_to_store() {
        let cwd = Path::new("/work");
        let err = parse_args(&args(&["audit"]), cwd, None).unwrap_err();
        assert!(err.contains("--profile"), "{err}");
        let Invocation::Audit(audit) = parse_args(
            &args(&["audit", "--profile", "p.toml", "--json"]),
            cwd,
            None,
        )
        .unwrap() else {
            panic!("expected audit");
        };
        assert_eq!(audit.profile, PathBuf::from("p.toml"));
        assert_eq!(audit.store, PathBuf::from("/work/crawlytic.sqlite"));
        assert_eq!(audit.lock, PathBuf::from("/work/crawlytic.sqlite.lock"));
        assert!(!audit.resume);
        assert!(!audit.export_dir.as_os_str().is_empty());
    }

    #[test]
    fn schedule_print_does_not_install_units() {
        let cwd = Path::new("/work");
        let Invocation::SchedulePrint(print) = parse_args(
            &args(&["schedule", "print", "--profile", "p.toml"]),
            cwd,
            None,
        )
        .unwrap() else {
            panic!("expected schedule print");
        };
        assert_eq!(print.profile, PathBuf::from("p.toml"));
        assert!(!HELP.to_ascii_lowercase().contains("systemctl enable"));
        assert!(HELP.contains("does not install"));
        assert!(HELP.contains("Email stays disabled"));
    }

    #[test]
    fn schedule_print_refuses_example_profile_until_time_and_timezone_are_set() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let err = render_schedule(ScheduleArgs {
            profile: root.join("profile.example.toml"),
            store: PathBuf::from("crawlytic.sqlite"),
            lock: PathBuf::from("crawlytic.sqlite.lock"),
            binary: PathBuf::from("crawlytic"),
            working_directory: root,
            env_file: PathBuf::from(".env"),
            json: false,
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("time") && err.contains("timezone"), "{err}");
    }

    #[test]
    fn usage_report_is_machine_readable_and_has_no_email() {
        let report = usage_report("audit requires --profile PATH");
        let json = report.to_json().unwrap();
        assert_eq!(report.exit_code, EXIT_USAGE);
        assert!(!report.email);
        assert!(json.contains("\"kind\": \"usage\""));
    }
}
