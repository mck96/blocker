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
                self.session_section(ui);
                ui.separator();
                self.rules_section(ui);
                ui.separator();
                self.schedule_section(ui);
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
                ui.label(egui::RichText::new(format!("{} host rules · {} path rules", s.host_rule_count, s.path_rule_count)).small().weak());
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
            ui.horizontal(|ui| {
                ui.add(
                    egui::Slider::new(&mut self.session_minutes, 5..=480)
                        .suffix(" min")
                        .text("length"),
                );
            });
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.session_lock, "Lock (cannot cancel early)");
                if ui.button("▶ Start focus session").clicked() {
                    let minutes = self.session_minutes;
                    let lock = self.session_lock;
                    self.command(
                        Request::StartSession { minutes, lock },
                        "Focus session started",
                    );
                }
            });
        }
    }

    fn rules_section(&mut self, ui: &mut egui::Ui) {
        ui.strong("Blocked sites");
        ui.label(
            egui::RichText::new(
                "Examples:  youtube.com  (also blocks music.youtube.com and all \
                 subdomains)  ·  *.reddit.com  ·  =mail.google.com (exact host)  ·  \
                 x.com/elonmusk/* (path — proxy only)",
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
                        let tag = if parsed.is_host_level() {
                            egui::RichText::new("[domain]").small().weak()
                        } else {
                            egui::RichText::new("[path · proxy]").small().color(egui::Color32::from_rgb(180, 140, 40))
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
        ui.collapsing("Schedule windows", |ui| {
            ui.label(
                egui::RichText::new("Used when enforcement is set to \"On a schedule\".")
                    .small()
                    .weak(),
            );
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

    fn options_section(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("Advanced", |ui| {
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
