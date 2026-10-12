//! blocker-tray — an optional system-tray (StatusNotifierItem) front-end.
//!
//! It is a thin client of the daemon: it shows the current blocking status and
//! offers quick actions (switch enforcement, take a break, open the settings
//! GUI). It needs a tray host that implements the StatusNotifierItem spec —
//! KDE/Plasma has one built in; GNOME needs the "AppIndicator and
//! KStatusNotifierItem" extension. If no host is present the icon simply will
//! not appear, but nothing breaks.

use std::process::Command;
use std::time::Duration;

use ksni::blocking::{Handle, TrayMethods};

use blocker_core::config::Enforcement;
use blocker_core::ipc::Request;

#[derive(Default)]
struct BlockerTray {
    reachable: bool,
    active: bool,
    reason: String,
    enforcement: Option<Enforcement>,
    breaks_left: u32,
    break_minutes: u32,
    on_break: bool,
}

impl ksni::Tray for BlockerTray {
    fn id(&self) -> String {
        "blocker".into()
    }

    fn title(&self) -> String {
        "Blocker".into()
    }

    fn icon_name(&self) -> String {
        // Generic freedesktop icon names present in most icon themes.
        if !self.reachable {
            "dialog-warning".into()
        } else if self.active {
            "security-high".into()
        } else {
            "security-low".into()
        }
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        let desc = if !self.reachable {
            "Daemon unavailable".to_string()
        } else {
            self.reason.clone()
        };
        ksni::ToolTip {
            title: "Blocker".into(),
            description: desc,
            icon_name: self.icon_name(),
            icon_pixmap: Vec::new(),
        }
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;

        if !self.reachable {
            return vec![
                StandardItem {
                    label: "Daemon unavailable".into(),
                    enabled: false,
                    ..Default::default()
                }
                .into(),
                MenuItem::Separator,
                StandardItem {
                    label: "Open settings".into(),
                    activate: Box::new(|_: &mut Self| open_gui()),
                    ..Default::default()
                }
                .into(),
                StandardItem {
                    label: "Quit tray".into(),
                    activate: Box::new(|_: &mut Self| std::process::exit(0)),
                    ..Default::default()
                }
                .into(),
            ];
        }

        let status_label = if self.active {
            format!("● {}", short(&self.reason))
        } else {
            format!("○ {}", short(&self.reason))
        };

        let mut items: Vec<ksni::MenuItem<Self>> = vec![
            StandardItem {
                label: status_label,
                enabled: false,
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            CheckmarkItem {
                label: "Always on".into(),
                checked: self.enforcement == Some(Enforcement::Always),
                activate: Box::new(|_: &mut Self| set_enforcement(Enforcement::Always)),
                ..Default::default()
            }
            .into(),
            CheckmarkItem {
                label: "On a schedule".into(),
                checked: self.enforcement == Some(Enforcement::Scheduled),
                activate: Box::new(|_: &mut Self| set_enforcement(Enforcement::Scheduled)),
                ..Default::default()
            }
            .into(),
            CheckmarkItem {
                label: "Off".into(),
                checked: self.enforcement == Some(Enforcement::Off),
                activate: Box::new(|_: &mut Self| set_enforcement(Enforcement::Off)),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
        ];

        if self.on_break {
            items.push(
                StandardItem {
                    label: "On a break…".into(),
                    enabled: false,
                    ..Default::default()
                }
                .into(),
            );
        } else {
            let mins = self.break_minutes;
            items.push(
                StandardItem {
                    label: format!("Take a {mins}-min break ({} left)", self.breaks_left),
                    enabled: self.breaks_left > 0,
                    activate: Box::new(|_: &mut Self| {
                        let _ = blocker_core::client::send(&Request::TakeBreak);
                    }),
                    ..Default::default()
                }
                .into(),
            );
        }

        items.push(MenuItem::Separator);
        items.push(
            StandardItem {
                label: "Open settings".into(),
                activate: Box::new(|_: &mut Self| open_gui()),
                ..Default::default()
            }
            .into(),
        );
        items.push(
            StandardItem {
                label: "Quit tray".into(),
                activate: Box::new(|_: &mut Self| std::process::exit(0)),
                ..Default::default()
            }
            .into(),
        );
        items
    }
}

fn set_enforcement(enforcement: Enforcement) {
    let _ = blocker_core::client::send(&Request::SetEnforcement { enforcement });
}

fn open_gui() {
    let _ = Command::new("blocker-gui").spawn();
}

fn short(s: &str) -> String {
    if s.len() > 40 {
        format!("{}…", &s[..39])
    } else {
        s.to_string()
    }
}

/// Pull the latest status from the daemon into the tray struct.
fn refresh(handle: &Handle<BlockerTray>) {
    match blocker_core::client::send(&Request::Status) {
        Ok(st) => {
            let on_break = st.break_remaining_secs.map(|r| r > 0).unwrap_or(false);
            handle.update(move |t: &mut BlockerTray| {
                t.reachable = true;
                t.active = st.blocking_active;
                t.reason = st.reason.clone();
                t.enforcement = Some(st.enforcement);
                t.breaks_left = st.breaks_left;
                t.break_minutes = st.break_minutes;
                t.on_break = on_break;
            });
        }
        Err(_) => {
            handle.update(|t: &mut BlockerTray| {
                t.reachable = false;
            });
        }
    }
}

fn main() {
    let handle = match BlockerTray::default().spawn() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "blocker-tray: could not register a tray icon ({e}).\n\
                 Your desktop may lack a StatusNotifierItem host. On GNOME, \
                 install the 'AppIndicator and KStatusNotifierItem' extension."
            );
            std::process::exit(1);
        }
    };
    // Poll the daemon and refresh the tray periodically.
    loop {
        refresh(&handle);
        std::thread::sleep(Duration::from_secs(3));
    }
}
