//! Blocker — desktop GUI front-end for the blockerd daemon.
//!
//! The GUI never touches the system directly; it only reads and writes the
//! daemon's configuration over the control socket. All real blocking happens
//! in the privileged daemon.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod client;

use std::time::{Duration, Instant};

use eframe::egui;

use blocker_core::config::{Config, Enforcement};
use blocker_core::ipc::{Request, Status};
use blocker_core::rule::SiteRule;
use blocker_core::schedule::Window;

const WEEKDAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([720.0, 640.0])
            .with_min_inner_size([560.0, 480.0])
            .with_title("Blocker"),
        ..Default::default()
    };
    eframe::run_native(
        "Blocker",
        options,
        Box::new(|_cc| Ok(Box::new(App::new()))),
    )
}

struct App {
    cfg: Config,
    status: Option<Status>,
    error: Option<String>,
    /// Local config edits not yet pushed to the daemon.
    dirty: bool,
    last_poll: Instant,
    new_rule: String,
    session_minutes: u32,
    session_lock: bool,
    toast: Option<(String, Instant)>,
}

impl App {
    fn new() -> Self {
        let mut app = App {
            cfg: Config::default(),
            status: None,
            error: None,
            dirty: false,
            last_poll: Instant::now() - Duration::from_secs(10),
            new_rule: String::new(),
            session_minutes: 60,
            session_lock: false,
            toast: None,
        };
        app.poll();
        app
    }

    fn poll(&mut self) {
        self.last_poll = Instant::now();
        match client::send(&Request::Status) {
            Ok(status) => {
                if !self.dirty {
                    self.cfg = status.config.clone();
                }
                self.status = Some(status);
                self.error = None;
            }
            Err(e) => self.error = Some(e),
        }
    }

    fn apply(&mut self) {
        match client::send(&Request::SetConfig {
            config: self.cfg.clone(),
        }) {
            Ok(status) => {
                self.cfg = status.config.clone();
                self.status = Some(status);
                self.dirty = false;
                self.toast(" Changes applied");
            }
            Err(e) => self.error = Some(e),
        }
    }

    fn command(&mut self, req: Request, ok_msg: &str) {
        match client::send(&req) {
            Ok(status) => {
                if !self.dirty {
                    self.cfg = status.config.clone();
                }
                self.status = Some(status);
                self.toast(ok_msg);
            }
            Err(e) => self.error = Some(e),
        }
    }

    fn toast(&mut self, msg: &str) {
        self.toast = Some((msg.to_string(), Instant::now()));
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.last_poll.elapsed() > Duration::from_secs(2) {
            self.poll();
        }
        ctx.request_repaint_after(Duration::from_secs(1));

        egui::TopBottomPanel::top("header").show(ctx, |ui| self.header(ui));
        if let Some(err) = self.error.clone() {
            egui::TopBottomPanel::top("err").show(ctx, |ui| {
                ui.add_space(4.0);
                ui.colored_label(egui::Color32::from_rgb(200, 60, 60), "⚠ Daemon unavailable");
                ui.label(egui::RichText::new(err).small());
                ui.add_space(4.0);
            });
        }
        egui::TopBottomPanel::bottom("footer").show(ctx, |ui| self.footer(ui));

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.enforcement_section(ui);
                ui.separator();
                self.network_section(ui);
                ui.separator();
                self.session_section(ui);
                ui.separator();
                self.rules_section(ui);
                ui.separator();
                self.schedule_section(ui);
                ui.separator();
                self.block_page_section(ui);
                ui.separator();
                self.options_section(ui);
            });
        });
    }
}

impl App {
    fn header(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.heading("🛡  Blocker");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let (active, reason) = match &self.status {
                    Some(s) => (s.blocking_active, s.reason.clone()),
                    None => (false, "connecting…".into()),
                };
                let (col, txt) = if active {
                    (egui::Color32::from_rgb(40, 170, 90), "BLOCKING ACTIVE")
                } else {
                    (egui::Color32::from_gray(130), "not blocking")
                };
                ui.label(egui::RichText::new(txt).color(col).strong());
                ui.label(egui::RichText::new(format!("· {reason}")).small().weak());
            });
        });
        ui.add_space(6.0);
    }

    fn footer(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if let Some(s) = &self.status {
                let dns = if s.dns_listening {
                    egui::RichText::new("DNS sinkhole: on").color(egui::Color32::from_rgb(40, 170, 90))
                } else {
                    egui::RichText::new("DNS sinkhole: OFF (hosts-only)").color(egui::Color32::from_rgb(200, 150, 40))
                };
                ui.label(dns.small());
                ui.separator();
                ui.label(
                    egui::RichText::new(format!(
                        "{} domain · {} path · {} keyword",
                        s.host_rule_count, s.path_rule_count, s.keyword_count
                    ))
                    .small()
                    .weak(),
                );
                if s.block_page_active {
                    ui.separator();
                    ui.label(
                        egui::RichText::new("block page: on")
                            .small()
                            .color(egui::Color32::from_rgb(40, 170, 90)),
                    );
                }
                if s.network_filter_active {
                    ui.separator();
                    ui.label(
                        egui::RichText::new("net filter: on")
                            .small()
                            .color(egui::Color32::from_rgb(40, 170, 90)),
                    );
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some((msg, t)) = &self.toast {
                    if t.elapsed() < Duration::from_secs(3) {
                        ui.label(egui::RichText::new(msg).color(egui::Color32::from_rgb(40, 170, 90)));
                    }
                }
            });
        });
        ui.add_space(4.0);
    }

    fn enforcement_section(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.strong("Enforcement");
        ui.label(egui::RichText::new("When should the blocklist be enforced?").small().weak());
        ui.horizontal(|ui| {
            let mut changed = None;
            if ui
                .radio_value(&mut self.cfg.enforcement, Enforcement::Always, "Always on")
                .clicked()
            {
                changed = Some(Enforcement::Always);
            }
            if ui
                .radio_value(&mut self.cfg.enforcement, Enforcement::Scheduled, "On a schedule")
                .clicked()
            {
                changed = Some(Enforcement::Scheduled);
            }
            if ui
                .radio_value(&mut self.cfg.enforcement, Enforcement::Off, "Off")
                .clicked()
            {
                changed = Some(Enforcement::Off);
            }
            if let Some(e) = changed {
                self.command(Request::SetEnforcement { enforcement: e }, "Enforcement updated");
            }
        });
    }

    fn network_section(&mut self, ui: &mut egui::Ui) {
        ui.strong("Enforcement reach");
        if ui
            .checkbox(
                &mut self.cfg.network_filter,
                "Network-level enforcement (works in every browser, defeats Secure DNS)",
            )
            .changed()
        {
            self.dirty = true;
        }
        ui.label(
            egui::RichText::new(
                "Strongly recommended. Inspects outgoing connections at the network \
                 layer (via nftables) and reads the hostname from the TLS handshake, \
                 so blocking works in ALL browsers with no per-browser setup — even \
                 when the browser uses its own encrypted DNS (DoH). Blocks whole \
                 domains, subdomains and keywords. (A specific HTTPS path still needs \
                 the proxy.)",
            )
            .small()
            .weak(),
        );
        if let Some(s) = &self.status {
            if self.cfg.network_filter && !s.network_filter_active {
                ui.colored_label(
                    egui::Color32::from_rgb(200, 150, 40),
                    "⚠ Enabled in config but not active — click \"Apply changes\" (needs root daemon + nftables).",
                );
            } else if s.network_filter_active {
                ui.colored_label(
                    egui::Color32::from_rgb(40, 170, 90),
                    "● Active — intercepting at the network layer.",
                );
            }
        }
    }

    fn session_section(&mut self, ui: &mut egui::Ui) {
        ui.strong("Focus session");
        ui.label(
            egui::RichText::new(
                "Force blocking on for a set time, regardless of the mode above.",
            )
            .small()
            .weak(),
        );

        let running = self
            .status
            .as_ref()
            .and_then(|s| s.session_remaining_secs)
            .filter(|r| *r > 0);

        if let Some(rem) = running {
            let locked = self.status.as_ref().map(|s| s.session_locked).unwrap_or(false);
            ui.horizontal(|ui| {
                ui.label(format!("⏳ {} remaining", fmt_duration(rem)));
                if locked {
                    ui.colored_label(egui::Color32::from_rgb(200, 150, 40), "🔒 locked");
                } else if ui.button("Stop session").clicked() {
                    self.command(Request::StopSession, "Session stopped");
                }
            });
            if locked {
                ui.label(
                    egui::RichText::new("This session is locked and will end on its own.")
                        .small()
                        .weak(),
                );
            }
        } else {
            // Quick presets (one click).
            ui.horizontal_wrapped(|ui| {
                ui.label("Quick:");
                if ui.button("🍅 Pomodoro 25m").clicked() {
                    self.start_session(25);
                }
                if ui.button("50m").clicked() {
                    self.start_session(50);
                }
                if ui.button("2h").clicked() {
                    self.start_session(120);
                }
                if ui.button("Until end of day").clicked() {
                    let mins = minutes_until_end_of_day();
                    if mins > 0 {
                        self.start_session(mins);
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.add(
                    egui::Slider::new(&mut self.session_minutes, 5..=480)
                        .suffix(" min")
                        .text("custom"),
                );
                if ui.button("▶ Start").clicked() {
                    self.start_session(self.session_minutes);
                }
            });
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.session_lock, "Lock (cannot cancel or take breaks)");
            });
        }

        // Break ("I need a break") — pause blocking briefly.
        if let Some(s) = &self.status {
            ui.add_space(6.0);
            if let Some(rem) = s.break_remaining_secs.filter(|r| *r > 0) {
                ui.colored_label(
                    egui::Color32::from_rgb(200, 150, 40),
                    format!("☕ On a break — {} left", fmt_duration(rem)),
                );
            } else {
                let left = s.breaks_left;
                let mins = s.break_minutes;
                ui.horizontal(|ui| {
                    let btn = egui::Button::new(format!("☕ Take a {mins}-min break"));
                    if ui.add_enabled(left > 0, btn).clicked() {
                        self.command(Request::TakeBreak, "Break started");
                    }
                    ui.label(
                        egui::RichText::new(format!("{left} break(s) left today"))
                            .small()
                            .weak(),
                    );
                });
            }
        }
    }

    fn start_session(&mut self, minutes: u32) {
        let lock = self.session_lock;
        self.command(
            Request::StartSession { minutes, lock },
            "Focus session started",
        );
    }

    fn rules_section(&mut self, ui: &mut egui::Ui) {
        ui.strong("Blocked sites");
        ui.label(
            egui::RichText::new(
                "Examples:  youtube.com  (also blocks music.youtube.com and all \
                 subdomains)  ·  *.reddit.com  ·  =mail.google.com (exact host)  ·  \
                 x.com/elonmusk/* and x.com/*elonmusk* (path — needs proxy)  ·  \
                 ~elonmusk (keyword: matches it anywhere in a host or URL)",
            )
            .small()
            .weak(),
        );

        ui.horizontal(|ui| {
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.new_rule)
                    .hint_text("add a site or pattern…")
                    .desired_width(360.0),
            );
            let submit = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if (ui.button("＋ Add").clicked() || submit) && !self.new_rule.trim().is_empty() {
                let pat = self.new_rule.trim().to_string();
                if blocker_core::rule::ParsedRule::parse(&pat).is_some() {
                    self.cfg.rules.push(SiteRule::new(pat));
                    self.new_rule.clear();
                    self.dirty = true;
                } else {
                    self.toast("⚠ not a valid pattern");
                }
            }
        });

        ui.add_space(4.0);

        let mut remove: Option<usize> = None;
        egui::Frame::group(ui.style()).show(ui, |ui| {
            if self.cfg.rules.is_empty() {
                ui.weak("No rules yet. Add a site above.");
            }
            for (i, rule) in self.cfg.rules.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    if ui.checkbox(&mut rule.enabled, "").changed() {
                        // mark dirty below via flag
                    }
                    let text = if rule.enabled {
                        egui::RichText::new(&rule.pattern)
                    } else {
                        egui::RichText::new(&rule.pattern).strikethrough().weak()
                    };
                    ui.label(text);
                    // classify for the user
                    if let Some(parsed) = rule.parse() {
                        let tag = match parsed.kind_label() {
                            "path" => egui::RichText::new("[path · proxy]")
                                .small()
                                .color(egui::Color32::from_rgb(180, 140, 40)),
                            "keyword" => egui::RichText::new("[keyword]")
                                .small()
                                .color(egui::Color32::from_rgb(120, 150, 210)),
                            _ => egui::RichText::new("[domain]").small().weak(),
                        };
                        ui.label(tag);
                    } else {
                        ui.colored_label(egui::Color32::from_rgb(200, 60, 60), "[invalid]");
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("🗑").clicked() {
                            remove = Some(i);
                        }
                    });
                });
            }
        });

        // Detect edits to enabled flags: cheap heuristic — compare to status.
        if let Some(s) = &self.status {
            if s.config.rules != self.cfg.rules {
                self.dirty = true;
            }
        }

        if let Some(i) = remove {
            self.cfg.rules.remove(i);
            self.dirty = true;
        }

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let apply = egui::Button::new(egui::RichText::new("💾 Apply changes").strong());
            if ui.add_enabled(self.dirty, apply).clicked() {
                self.apply();
            }
            if self.dirty {
                ui.colored_label(egui::Color32::from_rgb(200, 150, 40), "unsaved changes");
                if ui.button("Discard").clicked() {
                    if let Some(s) = &self.status {
                        self.cfg = s.config.clone();
                    }
                    self.dirty = false;
                }
            }
        });
    }

    fn schedule_section(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Schedule windows").default_open(true).show(ui, |ui| {
            ui.label(
                egui::RichText::new(
                    "Block only during these weekly time windows (e.g. 08:00–09:00). \
                     A window applies when enforcement is \"On a schedule\".",
                )
                .small()
                .weak(),
            );
            // If there are windows but we're not in Scheduled mode, offer a
            // one-click switch so the schedule actually takes effect.
            if !self.cfg.schedule.windows.is_empty()
                && self.cfg.enforcement != Enforcement::Scheduled
            {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        egui::Color32::from_rgb(200, 150, 40),
                        "⚠ These windows are not active yet.",
                    );
                    if ui.button("Activate schedule").clicked() {
                        self.cfg.enforcement = Enforcement::Scheduled;
                        self.command(
                            Request::SetEnforcement {
                                enforcement: Enforcement::Scheduled,
                            },
                            "Schedule activated",
                        );
                    }
                });
            }
            let mut remove: Option<usize> = None;
            let mut changed = false;
            for (i, w) in self.cfg.schedule.windows.iter_mut().enumerate() {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        for (d, label) in WEEKDAYS.iter().enumerate() {
                            let mut on = w.days.contains(&(d as u8));
                            if ui.toggle_value(&mut on, *label).changed() {
                                if on {
                                    if !w.days.contains(&(d as u8)) {
                                        w.days.push(d as u8);
                                    }
                                } else {
                                    w.days.retain(|x| *x != d as u8);
                                }
                                changed = true;
                            }
                        }
                    });
                    ui.horizontal(|ui| {
                        changed |= time_picker(ui, "from", &mut w.start_min);
                        changed |= time_picker(ui, "to", &mut w.end_min);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("remove").clicked() {
                                remove = Some(i);
                            }
                        });
                    });
                });
            }
            if let Some(i) = remove {
                self.cfg.schedule.windows.remove(i);
                changed = true;
            }
            if ui.button("＋ Add window").clicked() {
                self.cfg.schedule.windows.push(Window {
                    days: vec![0, 1, 2, 3, 4],
                    start_min: 9 * 60,
                    end_min: 17 * 60,
                });
                changed = true;
            }
            if changed {
                self.dirty = true;
            }
        });
    }

    fn block_page_section(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Motivational block page").default_open(true).show(ui, |ui| {
            if ui
                .checkbox(
                    &mut self.cfg.block_page,
                    "Show a page when a blocked site is opened (instead of a silent failure)",
                )
                .changed()
            {
                self.dirty = true;
            }
            ui.label(
                egui::RichText::new(
                    "Blocked sites then resolve to a local page server. For the page \
                     to appear cleanly on HTTPS sites you must trust the local CA \
                     (run packaging/trust-ca.sh). Otherwise the browser shows a \
                     certificate warning.",
                )
                .small()
                .weak(),
            );
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Title");
                if ui
                    .add(egui::TextEdit::singleline(&mut self.cfg.block_title).desired_width(320.0))
                    .changed()
                {
                    self.dirty = true;
                }
            });
            ui.label("Message");
            if ui
                .add(
                    egui::TextEdit::multiline(&mut self.cfg.block_message)
                        .desired_rows(2)
                        .desired_width(f32::INFINITY),
                )
                .changed()
            {
                self.dirty = true;
            }
            ui.label(
                egui::RichText::new(
                    "Changes are saved with \"Apply changes\" in the Blocked sites section.",
                )
                .small()
                .weak(),
            );
        });
    }

    fn options_section(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Advanced").default_open(false).show(ui, |ui| {
            if ui
                .checkbox(
                    &mut self.cfg.strict_block_doh,
                    "Strict mode: also block secure DNS (DoH/DoT) bootstrap hosts",
                )
                .changed()
            {
                self.dirty = true;
            }
            ui.label(
                egui::RichText::new(
                    "Strict mode stops browsers that use their own encrypted DNS \
                     from bypassing the blocklist. For guaranteed blocking, also \
                     turn off \"Secure DNS\" in your browser settings.",
                )
                .small()
                .weak(),
            );
            ui.add_space(6.0);
            if let Some(s) = &self.status {
                ui.label(egui::RichText::new(format!("Upstream resolvers: {}", s.upstreams.join(", "))).small().weak());
            }
        });
    }
}

fn time_picker(ui: &mut egui::Ui, label: &str, minutes: &mut u16) -> bool {
    ui.label(label);
    let mut h = (*minutes / 60) as i32;
    let mut m = (*minutes % 60) as i32;
    let mut changed = false;
    changed |= ui.add(egui::DragValue::new(&mut h).range(0..=23).prefix("h ")).changed();
    changed |= ui.add(egui::DragValue::new(&mut m).range(0..=59).prefix("m ")).changed();
    if changed {
        *minutes = (h as u16) * 60 + (m as u16);
    }
    changed
}

/// Minutes from now until 23:59 local time (for "block until end of day").
fn minutes_until_end_of_day() -> u32 {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return 60;
        }
        let now_min = tm.tm_hour * 60 + tm.tm_min;
        let end = 24 * 60; // midnight
        ((end - now_min).max(1)) as u32
    }
}

fn fmt_duration(secs: i64) -> String {
    let secs = secs.max(0);
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m:02}m {s:02}s")
    } else {
        format!("{m}m {s:02}s")
    }
}
