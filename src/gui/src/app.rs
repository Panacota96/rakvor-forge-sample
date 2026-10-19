//! The window. Drawing only: rules live in `state.rs`, work lives in the core (on a worker thread).

use crate::state::{GuiState, LANG_CHOICES, Phase};
use eframe::egui;
use rv_hashinv_core::{Event, HashAlgo, RunConfig, RunSummary, TOOL_VERSION};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

enum Msg {
    Event(Event),
    Done(Result<RunSummary, String>),
}

pub struct HashInvApp {
    state: GuiState,
    rx: Option<Receiver<Msg>>,
    cancel: Arc<AtomicBool>,
    started: Option<Instant>,
    notice: Option<String>,
}

impl HashInvApp {
    pub fn new() -> Self {
        HashInvApp {
            state: GuiState::default(),
            rx: None,
            cancel: Arc::new(AtomicBool::new(false)),
            started: None,
            notice: None,
        }
    }

    /// Starts with evidence already selected (paths given to the executable).
    pub fn with_inputs(paths: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut app = Self::new();
        for p in paths {
            app.state.add_input(p);
        }
        app
    }

    fn start(&mut self, ctx: &egui::Context) {
        let cfg: RunConfig = match self.state.to_config() {
            Ok(c) => c,
            Err(e) => {
                self.notice = Some(e);
                return;
            }
        };
        self.notice = None;
        self.state.start();
        self.cancel.store(false, Ordering::SeqCst);
        self.started = Some(Instant::now());
        let (tx, rx) = channel();
        self.rx = Some(rx);
        let cancel = self.cancel.clone();
        let repaint = ctx.clone();
        std::thread::spawn(move || {
            let tx2 = tx.clone();
            let r2 = repaint.clone();
            let mut sink = move |e: &Event| {
                let _ = tx2.send(Msg::Event(e.clone()));
                r2.request_repaint();
            };
            let result = rv_hashinv_core::run(&cfg, &mut sink, &cancel);
            let _ = tx.send(Msg::Done(result));
            repaint.request_repaint();
        });
    }

    fn drain(&mut self) {
        let Some(rx) = &self.rx else { return };
        let mut finished = false;
        while let Ok(m) = rx.try_recv() {
            match m {
                Msg::Event(e) => self.state.apply(&e),
                Msg::Done(Ok(_)) => finished = true,
                Msg::Done(Err(e)) => {
                    self.state.fail(e);
                    finished = true;
                }
            }
        }
        if finished {
            self.rx = None;
            self.started = None;
        }
    }

    fn evidence_section(&mut self, ui: &mut egui::Ui, enabled: bool) {
        ui.heading("1. Evidence");
        ui.label("Add one file, several files or whole folders (bulk review).");
        ui.add_enabled_ui(enabled, |ui| {
            ui.horizontal(|ui| {
                #[cfg(windows)]
                {
                    if ui.button("Add files…").clicked() {
                        if let Some(files) = rfd::FileDialog::new().pick_files() {
                            for f in files {
                                self.state.add_input(f);
                            }
                        }
                    }
                    if ui.button("Add folder…").clicked() {
                        if let Some(d) = rfd::FileDialog::new().pick_folder() {
                            self.state.add_input(d);
                        }
                    }
                }
                let entry = ui.add(egui::TextEdit::singleline(&mut self.state.path_entry).hint_text("…or type / paste a path").desired_width(320.0));
                let enter = entry.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.button("Add path").clicked() || enter {
                    self.state.add_typed_path();
                }
            });
            // Drag and drop from Explorer.
            let dropped: Vec<PathBuf> = ui.ctx().input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).filter(|p| !p.as_os_str().is_empty()).collect());
            for p in dropped {
                self.state.add_input(p);
            }
            let mut remove = None;
            egui::ScrollArea::vertical().max_height(110.0).id_salt("inputs").show(ui, |ui| {
                if self.state.inputs.is_empty() {
                    ui.weak("No evidence added yet. You can also drag files or folders onto this window.");
                }
                for (i, p) in self.state.inputs.iter().enumerate() {
                    ui.horizontal(|ui| {
                        if ui.small_button("x").on_hover_text("Remove").clicked() {
                            remove = Some(i);
                        }
                        ui.monospace(p.display().to_string());
                    });
                }
            });
            if let Some(i) = remove {
                self.state.remove_input(i);
            }
            let mut rec = self.state.recursive;
            if ui.checkbox(&mut rec, "Include subfolders").changed() {
                self.state.set_recursive(rec);
            }
        });
    }

    fn hashing_section(&mut self, ui: &mut egui::Ui, enabled: bool) {
        ui.heading("2. Hash algorithms (choose 1 or 2)");
        ui.add_enabled_ui(enabled, |ui| {
            ui.horizontal_wrapped(|ui| {
                for a in HashAlgo::ALL {
                    let mut on = self.state.selected.contains(&a);
                    let tip = if self.state.can_toggle(a) {
                        "Both selected algorithms are computed in the same read."
                    } else if on {
                        "At least one algorithm is required."
                    } else {
                        "Two algorithms are already selected: untick one first."
                    };
                    let r = ui
                        .add_enabled(
                            self.state.can_toggle(a),
                            egui::Checkbox::new(&mut on, a.name()),
                        )
                        .on_hover_text(tip)
                        .on_disabled_hover_text(tip);
                    if r.changed() {
                        if let Err(e) = self.state.toggle_algo(a) {
                            self.notice = Some(e);
                        }
                    }
                }
            });
        });
    }

    fn report_section(&mut self, ui: &mut egui::Ui, enabled: bool) {
        ui.heading("3. Reports");
        ui.add_enabled_ui(enabled, |ui| {
            egui::Grid::new("report-grid")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Report language");
                    let current = LANG_CHOICES
                        .iter()
                        .find(|(k, _)| *k == self.state.lang)
                        .map(|(_, v)| *v)
                        .unwrap_or("English");
                    let mut chosen = None;
                    egui::ComboBox::from_id_salt("lang")
                        .selected_text(current)
                        .show_ui(ui, |ui| {
                            for (k, v) in LANG_CHOICES {
                                if ui.selectable_label(self.state.lang == k, v).clicked() {
                                    chosen = Some(k);
                                }
                            }
                        });
                    if let Some(k) = chosen {
                        self.state.set_lang(k);
                    }
                    ui.end_row();
                    ui.label("Output folder");
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.state.out_dir)
                                .desired_width(300.0),
                        );
                        #[cfg(windows)]
                        if ui.button("Browse…").clicked() {
                            if let Some(d) = rfd::FileDialog::new().pick_folder() {
                                self.state.out_dir = d.display().to_string();
                            }
                        }
                    });
                    ui.end_row();
                    ui.label("Examiner");
                    ui.add(egui::TextEdit::singleline(&mut self.state.actor).desired_width(300.0));
                    ui.end_row();
                    ui.label("Case ID");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.state.case_id)
                            .hint_text("optional, e.g. CASE-2026-014")
                            .desired_width(300.0),
                    );
                    ui.end_row();
                });
        });
    }

    fn run_section(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if self.state.is_running() {
                if ui.add(egui::Button::new("Cancel")).clicked() {
                    self.cancel.store(true, Ordering::SeqCst);
                    self.notice = Some(
                        "Cancelling: finishing the current file, then writing partial reports…"
                            .into(),
                    );
                }
            } else if ui
                .add_enabled(self.state.can_start(), egui::Button::new("Start review"))
                .clicked()
            {
                let ctx = ui.ctx().clone();
                self.start(&ctx);
            }
            if let Some(n) = &self.notice {
                ui.colored_label(egui::Color32::from_rgb(181, 71, 8), n);
            }
        });
        ui.add_space(6.0);
        ui.add(
            egui::ProgressBar::new(self.state.fraction())
                .text(self.state.progress_text())
                .animate(self.state.is_running()),
        );
        let live = self.started.map(|s| s.elapsed().as_millis() as u64);
        ui.label(self.state.timing_text(live));
        if !self.state.current_item.is_empty() {
            ui.weak(format!("Now: {}", self.state.current_item));
        }
        match &self.state.phase {
            Phase::Failed(e) => {
                ui.colored_label(
                    egui::Color32::from_rgb(180, 35, 24),
                    format!("The review failed: {}", e),
                );
            }
            Phase::Finished | Phase::Cancelled => {
                if let Some(o) = self.state.outcome.clone() {
                    ui.separator();
                    let title = if self.state.phase == Phase::Cancelled {
                        "Cancelled — partial results"
                    } else {
                        "Done"
                    };
                    ui.strong(title);
                    ui.label(format!(
                        "{} files · {} errors · findings: {} high, {} medium, {} low, {} info",
                        o.items, o.errors, o.high, o.medium, o.low, o.info
                    ));
                    ui.horizontal(|ui| {
                        if ui.button("Open report").clicked() {
                            open_path(&o.report);
                        }
                        if ui.button("Open log folder").clicked() {
                            open_path(&o.log_dir);
                        }
                    });
                }
            }
            _ => {}
        }
        if !self.state.warnings.is_empty() {
            egui::CollapsingHeader::new(format!("Warnings ({})", self.state.warnings.len())).show(
                ui,
                |ui| {
                    for w in &self.state.warnings {
                        ui.label(w);
                    }
                },
            );
        }
    }
}

impl Default for HashInvApp {
    fn default() -> Self {
        Self::new()
    }
}

fn open_path(p: &Path) {
    #[cfg(windows)]
    let _ = std::process::Command::new("explorer").arg(p).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(p).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(p).spawn();
}

impl eframe::App for HashInvApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain();
        if self.state.is_running() {
            // Keep the elapsed timer moving even when no event arrives (large files).
            ui.ctx().request_repaint_after(Duration::from_millis(200));
        }
        egui::Panel::top("top").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong("RAKVOR · RV HashInv");
                ui.weak(format!("v{}", TOOL_VERSION));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.weak("Every action is written to a tamper-evident audit log.");
                });
            });
        });
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                let enabled = !self.state.is_running();
                self.evidence_section(ui, enabled);
                ui.separator();
                self.hashing_section(ui, enabled);
                ui.separator();
                self.report_section(ui, enabled);
                ui.separator();
                self.run_section(ui);
            });
        });
    }
}
