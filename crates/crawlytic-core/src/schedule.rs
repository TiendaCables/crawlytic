//! Local weekly schedule plans. Time and timezone must be chosen before a
//! timer or crontab is considered enabled. Units never send email.

use crate::profile::{Profile, ScheduleCadence, Weekday};
use serde::Serialize;
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleError {
    message: String,
}

impl ScheduleError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for ScheduleError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ScheduleError {}

/// Operator-chosen weekly fire time. Constructing this is what "enables"
/// a schedule; missing clock or timezone keeps the recorded Monday intent only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulePlan {
    pub cadence: ScheduleCadence,
    pub weekday: Weekday,
    pub hour: u8,
    pub minute: u8,
    pub timezone: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleExec {
    pub working_directory: PathBuf,
    pub binary: PathBuf,
    pub profile: PathBuf,
    pub store: PathBuf,
    pub lock: PathBuf,
    pub env_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleGuidance {
    pub plan: SchedulePlan,
    pub overlap: &'static str,
    pub restart: &'static str,
    pub email: bool,
    pub systemd_service: String,
    pub systemd_timer: String,
    pub crontab: String,
}

pub const OVERLAP_POLICY: &str = "prevented";
pub const RESTART_POLICY: &str = "oneshot Restart=no; Persistent=true fires missed weekly runs after boot; resume an incomplete crawl with audit --resume";

impl SchedulePlan {
    pub fn from_profile(profile: &Profile) -> Result<Self, ScheduleError> {
        if profile.completion_email {
            return Err(ScheduleError::new(
                "Completion email is not implemented and stays disabled. Leave completion_email = false. No messages or automations are created.",
            ));
        }
        match (
            profile.schedule_time.as_deref(),
            profile.schedule_timezone.as_deref(),
        ) {
            (Some(time), Some(timezone)) => {
                let (hour, minute) = parse_clock(time)?;
                let timezone = validate_timezone(timezone)?;
                Ok(Self {
                    cadence: profile.schedule_cadence,
                    weekday: profile.schedule_weekday,
                    hour,
                    minute,
                    timezone,
                })
            }
            _ => Err(ScheduleError::new(
                "Weekly Monday intent only: time and timezone unspecified; no scheduler is enabled. Choose schedule_time (HH:MM) and schedule_timezone before printing or installing a timer.",
            )),
        }
    }

    fn calendar_weekday(&self) -> &'static str {
        match self.weekday {
            Weekday::Monday => "Mon",
            Weekday::Tuesday => "Tue",
            Weekday::Wednesday => "Wed",
            Weekday::Thursday => "Thu",
            Weekday::Friday => "Fri",
            Weekday::Saturday => "Sat",
            Weekday::Sunday => "Sun",
        }
    }

    fn cron_weekday(&self) -> u8 {
        match self.weekday {
            Weekday::Sunday => 0,
            Weekday::Monday => 1,
            Weekday::Tuesday => 2,
            Weekday::Wednesday => 3,
            Weekday::Thursday => 4,
            Weekday::Friday => 5,
            Weekday::Saturday => 6,
        }
    }

    fn on_calendar(&self) -> String {
        format!(
            "{} *-*-* {:02}:{:02}:00",
            self.calendar_weekday(),
            self.hour,
            self.minute
        )
    }
}

impl ScheduleGuidance {
    pub fn render(plan: SchedulePlan, exec: &ScheduleExec) -> Result<Self, ScheduleError> {
        if plan.cadence != ScheduleCadence::Weekly {
            return Err(ScheduleError::new(
                "Only weekly cadence is supported for local timers",
            ));
        }
        let audit = format!(
            "{} audit --profile {} --store {} --lock {} --json",
            exec.binary.display(),
            exec.profile.display(),
            exec.store.display(),
            exec.lock.display()
        );
        let systemd_service = format!(
            "[Unit]\n\
Description=Crawlytic weekly headless audit\n\
After=network-online.target\n\
\n\
[Service]\n\
Type=oneshot\n\
WorkingDirectory={}\n\
EnvironmentFile=-{}\n\
ExecStart={audit}\n\
Restart=no\n\
# Overlap is refused by the binary (exit 3); a second run is not queued.\n\
# Credentials are resolved at runtime from the environment / EnvironmentFile.\n\
# Completion messages stay off. Do not add OnSuccess/OnFailure.\n",
            exec.working_directory.display(),
            exec.env_file.display()
        );
        let systemd_timer = format!(
            "[Unit]\n\
Description=Crawlytic weekly headless audit timer\n\
\n\
[Timer]\n\
OnCalendar={}\n\
Timezone={}\n\
Persistent=true\n\
AccuracySec=1min\n\
Unit=crawlytic-audit.service\n\
\n\
[Install]\n\
WantedBy=timers.target\n",
            plan.on_calendar(),
            plan.timezone
        );
        let crontab = format!(
            "MAILTO=\"\"\nCRON_TZ={}\n{} {} * * {} {}\n",
            plan.timezone,
            plan.minute,
            plan.hour,
            plan.cron_weekday(),
            audit
        );
        Ok(Self {
            plan,
            overlap: OVERLAP_POLICY,
            restart: RESTART_POLICY,
            email: false,
            systemd_service,
            systemd_timer,
            crontab,
        })
    }

    pub fn to_json(&self) -> Result<String, ScheduleError> {
        #[derive(Serialize)]
        struct Body<'a> {
            enabled: bool,
            email: bool,
            overlap: &'a str,
            restart: &'a str,
            systemd_service: &'a str,
            systemd_timer: &'a str,
            crontab: &'a str,
        }
        serde_json::to_string_pretty(&Body {
            enabled: true,
            email: self.email,
            overlap: self.overlap,
            restart: self.restart,
            systemd_service: &self.systemd_service,
            systemd_timer: &self.systemd_timer,
            crontab: &self.crontab,
        })
        .map_err(|err| ScheduleError::new(err.to_string()))
    }
}

pub fn default_lock_path(store: &Path) -> PathBuf {
    let mut path = store.as_os_str().to_os_string();
    path.push(".lock");
    PathBuf::from(path)
}

fn parse_clock(value: &str) -> Result<(u8, u8), ScheduleError> {
    let value = value.trim();
    let Some((hour, minute)) = value.split_once(':') else {
        return Err(ScheduleError::new(
            "schedule_time must be 24-hour HH:MM (for example 03:15)",
        ));
    };
    if hour.len() != 2 || minute.len() != 2 {
        return Err(ScheduleError::new(
            "schedule_time must be 24-hour HH:MM (zero-padded)",
        ));
    }
    if !hour.chars().all(|c| c.is_ascii_digit()) || !minute.chars().all(|c| c.is_ascii_digit()) {
        return Err(ScheduleError::new(
            "schedule_time must be 24-hour HH:MM (for example 03:15)",
        ));
    }
    let hour: u8 = hour
        .parse()
        .map_err(|_| ScheduleError::new("schedule_time hour is invalid"))?;
    let minute: u8 = minute
        .parse()
        .map_err(|_| ScheduleError::new("schedule_time minute is invalid"))?;
    if hour > 23 || minute > 59 {
        return Err(ScheduleError::new(
            "schedule_time must be 24-hour HH:MM (00:00–23:59)",
        ));
    }
    Ok((hour, minute))
}

fn validate_timezone(name: &str) -> Result<String, ScheduleError> {
    let name = name.trim();
    if name.is_empty()
        || name.contains(char::is_whitespace)
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '/' | '+' | '-'))
    {
        return Err(ScheduleError::new(
            "schedule_timezone must be an IANA name such as Europe/Madrid or UTC",
        ));
    }
    if name == "UTC" || name == "GMT" || name == "Etc/UTC" {
        return Ok(name.to_owned());
    }
    let zoneinfo = Path::new("/usr/share/zoneinfo");
    if zoneinfo.is_dir() {
        let path = zoneinfo.join(name);
        if !path.is_file() {
            return Err(ScheduleError::new(format!(
                "Unknown timezone {name}; choose an IANA name present on this host"
            )));
        }
    } else if !name.contains('/') {
        return Err(ScheduleError::new(
            "schedule_timezone must be an IANA name such as Europe/Madrid or UTC",
        ));
    }
    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;

    fn example_profile() -> Profile {
        Profile::load(include_str!("../../../profile.example.toml")).unwrap()
    }

    fn with_schedule(time: &str, timezone: &str, email: bool) -> Profile {
        let mut text = include_str!("../../../profile.example.toml").to_owned();
        text = text.replace(
            "schedule_weekday = \"monday\"\ncompletion_email = false",
            &format!(
                "schedule_weekday = \"monday\"\nschedule_time = \"{time}\"\nschedule_timezone = \"{timezone}\"\ncompletion_email = {email}"
            ),
        );
        Profile::load(&text).unwrap()
    }

    fn exec() -> ScheduleExec {
        ScheduleExec {
            working_directory: PathBuf::from("/var/lib/crawlytic"),
            binary: PathBuf::from("/usr/local/bin/crawlytic"),
            profile: PathBuf::from("/var/lib/crawlytic/profile.local.toml"),
            store: PathBuf::from("/var/lib/crawlytic/crawlytic.sqlite"),
            lock: PathBuf::from("/var/lib/crawlytic/crawlytic.sqlite.lock"),
            env_file: PathBuf::from("/var/lib/crawlytic/.env"),
        }
    }

    #[test]
    fn schedule_is_not_enabled_without_time_and_timezone() {
        let profile = example_profile();
        let err = SchedulePlan::from_profile(&profile)
            .unwrap_err()
            .to_string();
        assert!(err.contains("time") && err.contains("timezone"), "{err}");
        assert!(
            err.contains("no scheduler") || err.contains("not enabled"),
            "{err}"
        );
    }

    #[test]
    fn operator_must_choose_clock_and_timezone_before_units_are_rendered() {
        let profile = with_schedule("03:15", "Europe/Madrid", false);
        let plan = SchedulePlan::from_profile(&profile).unwrap();
        assert_eq!(plan.hour, 3);
        assert_eq!(plan.minute, 15);
        assert_eq!(plan.timezone, "Europe/Madrid");
        assert_eq!(plan.weekday, Weekday::Monday);
        let guidance = ScheduleGuidance::render(plan, &exec()).unwrap();
        assert!(!guidance.email);
        assert_eq!(guidance.overlap, OVERLAP_POLICY);
        assert!(
            guidance
                .systemd_timer
                .contains("OnCalendar=Mon *-*-* 03:15:00")
        );
        assert!(guidance.systemd_timer.contains("Timezone=Europe/Madrid"));
        assert!(guidance.systemd_timer.contains("Persistent=true"));
        assert!(guidance.systemd_service.contains("Type=oneshot"));
        assert!(guidance.systemd_service.contains("Restart=no"));
        assert!(guidance.systemd_service.contains("audit --profile"));
        assert!(guidance.systemd_service.contains("--lock"));
        assert!(
            !guidance
                .systemd_service
                .to_ascii_lowercase()
                .contains("mail"),
            "{}",
            guidance.systemd_service
        );
        assert!(
            !guidance.systemd_timer.to_ascii_lowercase().contains("mail"),
            "{}",
            guidance.systemd_timer
        );
        assert!(guidance.crontab.contains("CRON_TZ=Europe/Madrid"));
        assert!(guidance.crontab.contains("MAILTO=\"\""));
        assert!(guidance.crontab.contains("15 3 * * 1"));
        assert!(
            !guidance.crontab.contains("MAILTO=root"),
            "{}",
            guidance.crontab
        );
    }

    #[test]
    fn completion_email_blocks_schedule_enablement() {
        let profile = with_schedule("03:15", "Europe/Madrid", true);
        let err = SchedulePlan::from_profile(&profile)
            .unwrap_err()
            .to_string();
        assert!(err.to_ascii_lowercase().contains("email"), "{err}");
    }

    #[test]
    fn invalid_clock_or_timezone_is_rejected() {
        assert!(
            SchedulePlan::from_profile(&with_schedule("25:00", "Europe/Madrid", false)).is_err()
        );
        assert!(
            SchedulePlan::from_profile(&with_schedule("3:15", "Europe/Madrid", false)).is_err()
        );
        assert!(SchedulePlan::from_profile(&with_schedule("03:15", "Not a zone", false)).is_err());
    }
}
