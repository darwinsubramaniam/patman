//! `patman tui` — a terminal UI over the manifest, for editing and maintenance.
//!
//! It is a front end, not a second implementation: every change goes through the
//! same `cmds` function the CLI calls, so validation, policy signing and the
//! order of writes stay in one place. The TUI only collects the arguments.
//!
//! Anything that might prompt — a token value, the vault passphrase — runs with
//! the TUI suspended, on the plain terminal, through the existing hidden-input
//! prompts. The TUI itself never reads a token file and has no field a token
//! value could be typed into, so it adds no new path for a secret to reach the
//! screen.

use std::io::{self, Write};

use ratatui::Frame;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    self as term, ClearType, EnterAlternateScreen, enable_raw_mode,
};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Terminal};

use crate::cmds::{self, Ctx, Edits};
use crate::error::{Result, bail};
use crate::manifest::{Approval, Entry, Manifest};
use crate::token;
use crate::vault;

pub fn run(ctx: &Ctx) -> Result<()> {
    // Same rule as the passphrase prompts: a tool call with no terminal has no
    // business driving an editor that can change policy.
    if !vault::has_tty() {
        return bail("patman tui needs a terminal — run it yourself in a terminal window");
    }
    let mut app = App::new(ctx)?;
    let mut terminal = ratatui::init();
    let result = app.event_loop(&mut terminal);
    ratatui::restore();
    result
}

// ------------------------------------------------------------------- model

#[derive(Clone, Copy, PartialEq, Eq)]
enum FileState {
    Missing,
    Plaintext,
    Sealed,
}

/// One service: a manifest entry, a token file, or both.
struct Row {
    service: String,
    entry: Option<Entry>,
    file: FileState,
}

fn load_rows(ctx: &Ctx) -> Result<Vec<Row>> {
    let manifest = Manifest::load(&ctx.manifest_path)?;
    let mut names: Vec<String> = manifest.entries.keys().cloned().collect();
    for f in token::list_files(&ctx.dir)? {
        if !manifest.entries.contains_key(&f) {
            names.push(f);
        }
    }
    names.sort();
    Ok(names
        .into_iter()
        .map(|service| {
            let file = if !token::exists(&service) {
                FileState::Missing
            } else if token::is_sealed(&service) {
                FileState::Sealed
            } else {
                FileState::Plaintext
            };
            Row {
                entry: manifest.get(&service).cloned(),
                service,
                file,
            }
        })
        .collect())
}

fn session_open() -> bool {
    #[cfg(unix)]
    {
        crate::agent::is_running()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Split a hosts field on commas and whitespace.
fn parse_hosts(s: &str) -> Vec<String> {
    s.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|h| !h.is_empty())
        .map(str::to_string)
        .collect()
}

/// Turn a submitted edit form into `describe` edits that change only what the
/// user changed. That matters under a sealed vault: `describe` asks for the
/// passphrase only when the policy moves, so passing unchanged fields through
/// is harmless, but passing `approval` at all on a plaintext install is an error.
fn edits_from(
    prev: Option<&Entry>,
    description: &str,
    username: &str,
    hosts: &str,
    allow_exec: bool,
    approval: Option<Approval>,
) -> Edits {
    let username = username.trim();
    let hosts = parse_hosts(hosts);
    let prev_user = prev.and_then(|p| p.username.as_deref());
    let prev_hosts: &[String] = prev.map(|p| p.hosts.as_slice()).unwrap_or(&[]);
    let prev_exec = prev.is_some_and(|p| p.allow_exec);
    let prev_approval = prev.map(|p| p.approval).unwrap_or_default();

    Edits {
        description: Some(description.trim().to_string()),
        clear_username: username.is_empty() && prev_user.is_some(),
        username: (!username.is_empty() && Some(username) != prev_user)
            .then(|| username.to_string()),
        clear_hosts: hosts.is_empty() && !prev_hosts.is_empty(),
        hosts: if hosts.as_slice() == prev_hosts {
            Vec::new()
        } else {
            hosts
        },
        allow_exec: (allow_exec != prev_exec).then_some(allow_exec),
        approval: approval.filter(|a| *a != prev_approval),
        sign: false,
    }
}

// -------------------------------------------------------------- text input

#[derive(Default, Clone)]
struct Input {
    value: String,
    /// Cursor position in chars, not bytes.
    cursor: usize,
}

impl Input {
    fn new(value: &str) -> Self {
        Self {
            value: value.to_string(),
            cursor: value.chars().count(),
        }
    }

    fn byte_at(&self, char_idx: usize) -> usize {
        self.value
            .char_indices()
            .nth(char_idx)
            .map(|(b, _)| b)
            .unwrap_or(self.value.len())
    }

    /// Returns true when the key was a text-editing key.
    fn handle(&mut self, key: KeyEvent) -> bool {
        let len = self.value.chars().count();
        match key.code {
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.value.clear();
                self.cursor = 0;
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                let at = self.byte_at(self.cursor);
                self.value.insert(at, c);
                self.cursor += 1;
            }
            KeyCode::Backspace if self.cursor > 0 => {
                self.cursor -= 1;
                let at = self.byte_at(self.cursor);
                self.value.remove(at);
            }
            KeyCode::Delete if self.cursor < len => {
                let at = self.byte_at(self.cursor);
                self.value.remove(at);
            }
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(len),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = len,
            KeyCode::Backspace | KeyCode::Delete => {}
            _ => return false,
        }
        true
    }
}

// -------------------------------------------------------------------- forms

enum FieldKind {
    Text(Input),
    Toggle(bool),
    Approval(Approval),
}

struct Field {
    label: &'static str,
    hint: &'static str,
    kind: FieldKind,
}

impl Field {
    fn text(label: &'static str, hint: &'static str, value: &str) -> Self {
        Self {
            label,
            hint,
            kind: FieldKind::Text(Input::new(value)),
        }
    }

    fn text_value(&self) -> &str {
        match &self.kind {
            FieldKind::Text(i) => &i.value,
            _ => "",
        }
    }
}

enum FormKind {
    Edit(String),
    New,
    Migrate,
    Unlock,
}

struct Form {
    title: String,
    kind: FormKind,
    fields: Vec<Field>,
    focus: usize,
    note: Option<&'static str>,
    error: Option<String>,
}

impl Form {
    fn edit(row: &Row, sealed: bool) -> Self {
        let e = row.entry.as_ref();
        let mut fields = vec![
            Field::text(
                "Description",
                "which account/site, which scopes",
                e.map(|e| e.description.as_str()).unwrap_or(""),
            ),
            Field::text(
                "Username",
                "for Basic auth; empty = Bearer only",
                e.and_then(|e| e.username.as_deref()).unwrap_or(""),
            ),
            Field::text(
                "Hosts",
                "comma-separated; exact or *.example.com",
                &e.map(|e| e.hosts.join(", ")).unwrap_or_default(),
            ),
            Field {
                label: "Allow exec",
                hint: "space toggles; lets `patman exec` use it",
                kind: FieldKind::Toggle(e.is_some_and(|e| e.allow_exec)),
            },
        ];
        if sealed {
            fields.push(Field {
                label: "Approval",
                hint: "space toggles session / request",
                kind: FieldKind::Approval(e.map(|e| e.approval).unwrap_or_default()),
            });
        }
        Self {
            title: format!(" Edit {} ", row.service),
            kind: FormKind::Edit(row.service.clone()),
            fields,
            focus: 0,
            note: sealed
                .then_some("Changing username, hosts, exec or approval asks for the passphrase."),
            error: None,
        }
    }

    fn new_token() -> Self {
        Self {
            title: " New token ".into(),
            kind: FormKind::New,
            fields: vec![
                Field::text("Service", "file name under ~/.pat/", ""),
                Field::text("Description", "which account/site, which scopes", ""),
                Field::text("Username", "optional, for Basic auth", ""),
                Field::text("Hosts", "comma-separated; pin where it may be sent", ""),
            ],
            focus: 0,
            note: Some("The token value is asked for next, on the terminal, with echo off."),
            error: None,
        }
    }

    fn migrate() -> Self {
        Self {
            title: " Migrate legacy file ".into(),
            kind: FormKind::Migrate,
            fields: vec![
                Field::text("Service", "name to store it under", ""),
                Field::text("From", "path; empty = ~/.<service>_pat", ""),
            ],
            focus: 0,
            note: None,
            error: None,
        }
    }

    fn unlock() -> Self {
        Self {
            title: " Unlock session ".into(),
            kind: FormKind::Unlock,
            fields: vec![Field::text("Minutes", "how long the session lasts", "15")],
            focus: 0,
            note: Some("The vault passphrase is asked for next, on the terminal."),
            error: None,
        }
    }

    fn handle(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1) % self.fields.len(),
            KeyCode::BackTab | KeyCode::Up => {
                self.focus = (self.focus + self.fields.len() - 1) % self.fields.len();
            }
            _ => match &mut self.fields[self.focus].kind {
                FieldKind::Text(input) => {
                    input.handle(key);
                }
                FieldKind::Toggle(b) => {
                    if matches!(
                        key.code,
                        KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right
                    ) {
                        *b = !*b;
                    }
                }
                FieldKind::Approval(a) => {
                    if matches!(
                        key.code,
                        KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right
                    ) {
                        *a = match a {
                            Approval::Session => Approval::Request,
                            Approval::Request => Approval::Session,
                        };
                    }
                }
            },
        }
    }
}

// ----------------------------------------------------------------- actions

/// Something to run against `cmds`, with the TUI suspended.
enum Action {
    Describe(String, Edits),
    Save {
        service: String,
        description: Option<String>,
        username: Option<String>,
        hosts: Vec<String>,
    },
    Delete(String),
    Sign(String),
    Migrate(String, Option<std::path::PathBuf>),
    FixPerms,
    Doctor,
    Orphans,
    Unlock(u64),
    Lock,
    Status,
    VaultInit,
    VaultSeal,
}

impl Action {
    fn title(&self) -> String {
        match self {
            Action::Describe(s, _) => format!("patman describe {s}"),
            Action::Save { service, .. } => format!("patman save {service}"),
            Action::Delete(s) => format!("patman delete {s}"),
            Action::Sign(s) => format!("patman describe {s} --sign"),
            Action::Migrate(s, _) => format!("patman migrate {s}"),
            Action::FixPerms => "patman fix-perms".into(),
            Action::Doctor => "patman doctor".into(),
            Action::Orphans => "patman orphans".into(),
            Action::Unlock(m) => format!("patman unlock --minutes {m}"),
            Action::Lock => "patman lock".into(),
            Action::Status => "patman status".into(),
            Action::VaultInit => "patman vault init".into(),
            Action::VaultSeal => "patman vault seal".into(),
        }
    }

    fn run(self, ctx: &Ctx) -> Result<()> {
        match self {
            Action::Describe(s, edits) => cmds::describe(ctx, &s, edits),
            Action::Save {
                service,
                description,
                username,
                hosts,
            } => cmds::save(ctx, &service, description, username, hosts, false),
            Action::Delete(s) => cmds::delete(ctx, &s, true),
            Action::Sign(s) => cmds::describe(
                ctx,
                &s,
                Edits {
                    sign: true,
                    ..Edits::default()
                },
            ),
            Action::Migrate(s, from) => cmds::migrate(ctx, &s, from),
            Action::FixPerms => cmds::fix_perms(ctx),
            Action::Doctor => cmds::doctor(ctx),
            Action::Orphans => cmds::orphans(ctx),
            Action::Unlock(m) => cmds::unlock(m.saturating_mul(60)),
            Action::Lock => cmds::lock(),
            Action::Status => cmds::status(),
            Action::VaultInit => cmds::vault_init(ctx),
            Action::VaultSeal => cmds::vault_seal(ctx),
        }
    }
}

/// Leave the alternate screen, run `action` on the plain terminal so its
/// prompts and output work exactly as they do from the CLI, then come back.
fn suspended(terminal: &mut DefaultTerminal, ctx: &Ctx, action: Action) -> io::Result<bool> {
    ratatui::restore();
    let mut out = io::stdout();
    writeln!(out, "\n── {} ──\n", action.title())?;
    let ok = match action.run(ctx) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("patman: {e}");
            false
        }
    };
    write!(out, "\nPress Enter to return to patman tui…")?;
    out.flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;

    // A fresh terminal rather than `terminal.clear()`: clear asks the terminal
    // for the cursor position and blocks on the reply, which a terminal that
    // does not answer DSR never sends. A new one starts from an empty buffer on
    // a cleared screen, so the next draw repaints everything.
    enable_raw_mode()?;
    execute!(
        io::stdout(),
        EnterAlternateScreen,
        term::Clear(ClearType::All)
    )?;
    *terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    Ok(ok)
}

// --------------------------------------------------------------------- app

enum Modal {
    Form(Form),
    ConfirmDelete { service: String, input: Input },
    Help,
}

struct App<'a> {
    ctx: &'a Ctx,
    rows: Vec<Row>,
    /// Indices into `rows` that match the filter.
    visible: Vec<usize>,
    list: ListState,
    filter: Input,
    filtering: bool,
    modal: Option<Modal>,
    status: Option<(String, bool)>,
    sealed: bool,
    session: bool,
    quit: bool,
}

impl<'a> App<'a> {
    fn new(ctx: &'a Ctx) -> Result<Self> {
        let mut app = Self {
            ctx,
            rows: Vec::new(),
            visible: Vec::new(),
            list: ListState::default(),
            filter: Input::default(),
            filtering: false,
            modal: None,
            status: None,
            sealed: false,
            session: false,
            quit: false,
        };
        app.reload(None)?;
        Ok(app)
    }

    /// Re-read everything from disk, selecting `focus` if given, else keeping
    /// the current selection.
    fn reload(&mut self, focus: Option<String>) -> Result<()> {
        let keep = focus.or_else(|| self.selected().map(|r| r.service.clone()));
        self.rows = load_rows(self.ctx)?;
        self.sealed = vault::is_sealed_install();
        self.session = self.sealed && session_open();
        self.refilter();
        if let Some(name) = keep
            && let Some(pos) = self
                .visible
                .iter()
                .position(|&i| self.rows[i].service == name)
        {
            self.list.select(Some(pos));
        }
        Ok(())
    }

    fn refilter(&mut self) {
        let needle = self.filter.value.to_lowercase();
        self.visible = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                needle.is_empty() || {
                    let e = r.entry.as_ref();
                    format!(
                        "{} {} {}",
                        r.service,
                        e.map(|e| e.description.as_str()).unwrap_or(""),
                        e.and_then(|e| e.username.as_deref()).unwrap_or("")
                    )
                    .to_lowercase()
                    .contains(&needle)
                }
            })
            .map(|(i, _)| i)
            .collect();
        let sel = self
            .list
            .selected()
            .unwrap_or(0)
            .min(self.visible.len().saturating_sub(1));
        self.list.select((!self.visible.is_empty()).then_some(sel));
    }

    fn selected(&self) -> Option<&Row> {
        self.list
            .selected()
            .and_then(|i| self.visible.get(i))
            .map(|&i| &self.rows[i])
    }

    fn event_loop(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        while !self.quit {
            terminal.draw(|f| self.draw(f))?;
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            if let Some(action) = self.on_key(key) {
                let title = action.title();
                // A service that did not exist before should be selected once
                // it does, so the result of the action is on screen.
                let focus = match &action {
                    Action::Save { service, .. } | Action::Migrate(service, _) => {
                        Some(service.clone())
                    }
                    _ => None,
                };
                let ok = suspended(terminal, self.ctx, action)?;
                self.status = Some((
                    format!("{title}: {}", if ok { "done" } else { "failed" }),
                    ok,
                ));
                if let Err(e) = self.reload(focus) {
                    self.status = Some((e.to_string(), false));
                }
            }
        }
        Ok(())
    }

    fn on_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.quit = true;
            return None;
        }
        if let Some(modal) = self.modal.take() {
            return self.on_modal_key(modal, key);
        }
        if self.filtering {
            match key.code {
                KeyCode::Esc => {
                    self.filter = Input::default();
                    self.filtering = false;
                }
                KeyCode::Enter => self.filtering = false,
                KeyCode::Up | KeyCode::Down => self.move_selection(key.code),
                _ => {
                    self.filter.handle(key);
                }
            }
            self.refilter();
            return None;
        }

        self.status = None;
        let service = self.selected().map(|r| r.service.clone());
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Up | KeyCode::Down | KeyCode::Char('k') | KeyCode::Char('j') => {
                self.move_selection(key.code)
            }
            KeyCode::Home | KeyCode::Char('g') => self.list.select_first(),
            KeyCode::End | KeyCode::Char('G') => {
                self.list.select(self.visible.len().checked_sub(1))
            }
            KeyCode::Char('/') => self.filtering = true,
            KeyCode::Char('?') => self.modal = Some(Modal::Help),
            KeyCode::Char('R') => {
                if let Err(e) = self.reload(None) {
                    self.status = Some((e.to_string(), false));
                }
            }
            KeyCode::Char('n') => self.modal = Some(Modal::Form(Form::new_token())),
            KeyCode::Char('m') => self.modal = Some(Modal::Form(Form::migrate())),
            KeyCode::Char('f') => return Some(Action::FixPerms),
            KeyCode::Char('D') => return Some(Action::Doctor),
            KeyCode::Char('o') => return Some(Action::Orphans),
            KeyCode::Char('S') => return Some(Action::Status),
            KeyCode::Char('V') => {
                return Some(if self.sealed {
                    Action::VaultSeal
                } else {
                    Action::VaultInit
                });
            }
            KeyCode::Char('u') if self.sealed => {
                self.modal = Some(Modal::Form(Form::unlock()));
            }
            KeyCode::Char('l') if self.sealed => return Some(Action::Lock),

            // Everything below acts on the selected service.
            _ if service.is_none() => {}
            KeyCode::Enter | KeyCode::Char('e') => {
                let form = Form::edit(self.selected()?, self.sealed);
                self.modal = Some(Modal::Form(form));
            }
            KeyCode::Char('r') => {
                // Rotate keeps the description; a service with no entry yet
                // has none to keep, so it goes through the new-token form.
                let row = self.selected()?;
                if row.entry.is_none() {
                    let mut form = Form::new_token();
                    form.fields[0] =
                        Field::text("Service", "file name under ~/.pat/", &row.service);
                    form.focus = 1;
                    self.modal = Some(Modal::Form(form));
                } else {
                    return Some(Action::Save {
                        service: row.service.clone(),
                        description: None,
                        username: None,
                        hosts: Vec::new(),
                    });
                }
            }
            KeyCode::Char('s') if self.sealed => return service.map(Action::Sign),
            KeyCode::Char('x') | KeyCode::Delete => {
                self.modal = Some(Modal::ConfirmDelete {
                    service: service?,
                    input: Input::default(),
                });
            }
            _ => {}
        }
        None
    }

    fn move_selection(&mut self, code: KeyCode) {
        match code {
            KeyCode::Up | KeyCode::Char('k') => self.list.select_previous(),
            _ => self.list.select_next(),
        }
        // ListState clamps at render time; clamp here too so `selected()` is
        // right before the next draw.
        if let Some(i) = self.list.selected()
            && i >= self.visible.len()
        {
            self.list.select(self.visible.len().checked_sub(1));
        }
    }

    fn on_modal_key(&mut self, modal: Modal, key: KeyEvent) -> Option<Action> {
        match modal {
            Modal::Help => None,
            Modal::ConfirmDelete { service, mut input } => match key.code {
                KeyCode::Esc => None,
                KeyCode::Enter if input.value == service => Some(Action::Delete(service)),
                KeyCode::Enter => {
                    self.modal = Some(Modal::ConfirmDelete { service, input });
                    None
                }
                _ => {
                    input.handle(key);
                    self.modal = Some(Modal::ConfirmDelete { service, input });
                    None
                }
            },
            Modal::Form(mut form) => match key.code {
                KeyCode::Esc => None,
                KeyCode::Enter => match self.submit(&form) {
                    Ok(action) => Some(action),
                    Err(e) => {
                        form.error = Some(e.to_string());
                        self.modal = Some(Modal::Form(form));
                        None
                    }
                },
                _ => {
                    form.error = None;
                    form.handle(key);
                    self.modal = Some(Modal::Form(form));
                    None
                }
            },
        }
    }

    fn submit(&self, form: &Form) -> Result<Action> {
        let text = |i: usize| form.fields[i].text_value().trim().to_string();
        let opt = |s: String| (!s.is_empty()).then_some(s);
        match &form.kind {
            FormKind::Edit(service) => {
                if text(0).is_empty() {
                    return bail("a description is required");
                }
                let allow_exec = matches!(form.fields[3].kind, FieldKind::Toggle(true));
                let approval = form.fields.get(4).and_then(|f| match f.kind {
                    FieldKind::Approval(a) => Some(a),
                    _ => None,
                });
                let prev = self
                    .rows
                    .iter()
                    .find(|r| &r.service == service)
                    .and_then(|r| r.entry.as_ref());
                let edits = edits_from(prev, &text(0), &text(1), &text(2), allow_exec, approval);
                Ok(Action::Describe(service.clone(), edits))
            }
            FormKind::New => {
                let service = text(0);
                if service.is_empty() {
                    return bail("a service name is required");
                }
                crate::paths::validate_service(&service)?;
                if text(1).is_empty() {
                    return bail("a description is required — it is what makes a token findable");
                }
                Ok(Action::Save {
                    service,
                    description: opt(text(1)),
                    username: opt(text(2)),
                    hosts: parse_hosts(&text(3)),
                })
            }
            FormKind::Migrate => {
                let service = text(0);
                crate::paths::validate_service(&service)?;
                Ok(Action::Migrate(service, opt(text(1)).map(Into::into)))
            }
            FormKind::Unlock => match text(0).parse::<u64>() {
                Ok(m) if m > 0 => Ok(Action::Unlock(m)),
                _ => bail("minutes must be a positive whole number"),
            },
        }
    }

    // ------------------------------------------------------------- drawing

    fn draw(&mut self, f: &mut Frame) {
        let [header, body, footer] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .areas(f.area());

        f.render_widget(self.header_line(), header);

        let [left, right] =
            Layout::horizontal([Constraint::Percentage(35), Constraint::Percentage(65)])
                .areas(body);
        self.draw_list(f, left);
        self.draw_detail(f, right);
        f.render_widget(self.footer_line(), footer);

        match &self.modal {
            Some(Modal::Form(form)) => draw_form(f, form),
            Some(Modal::ConfirmDelete { service, input }) => draw_confirm(f, service, input),
            Some(Modal::Help) => draw_help(f),
            None => {}
        }
    }

    fn header_line(&self) -> Line<'static> {
        let vault = if !self.sealed {
            Span::styled("vault: none (plaintext)", Style::new().fg(Color::Yellow))
        } else if self.session {
            Span::styled(
                "vault: sealed · session open",
                Style::new().fg(Color::Green),
            )
        } else {
            Span::styled("vault: sealed · locked", Style::new().fg(Color::Cyan))
        };
        Line::from(vec![
            " patman ".bold().reversed(),
            format!("  {}  ", self.ctx.dir.display()).dim(),
            vault,
            format!("  {} service(s)", self.rows.len()).dim(),
        ])
    }

    fn footer_line(&self) -> Line<'static> {
        if let Some((msg, ok)) = &self.status {
            let color = if *ok { Color::Green } else { Color::Red };
            return Line::from(Span::styled(format!(" {msg}"), Style::new().fg(color)));
        }
        if self.filtering {
            return Line::from(" type to filter · Enter keep · Esc clear".dim());
        }
        let mut keys = vec![
            ("e", "edit"),
            ("n", "new"),
            ("r", "rotate"),
            ("x", "delete"),
        ];
        if self.sealed {
            keys.push(("s", "sign"));
            keys.push(if self.session {
                ("l", "lock")
            } else {
                ("u", "unlock")
            });
        }
        keys.extend([("/", "filter"), ("?", "help"), ("q", "quit")]);
        let mut spans = vec![Span::raw(" ")];
        for (k, what) in keys {
            spans.push(k.bold().cyan());
            spans.push(format!(" {what}  ").into());
        }
        Line::from(spans)
    }

    fn draw_list(&mut self, f: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .visible
            .iter()
            .map(|&i| {
                let r = &self.rows[i];
                let (mark, style) = match (&r.entry, r.file) {
                    (_, FileState::Missing) => ("!", Style::new().fg(Color::Red)),
                    (None, _) => ("?", Style::new().fg(Color::Yellow)),
                    (Some(e), _) if e.hosts.is_empty() => ("~", Style::new().fg(Color::Yellow)),
                    _ => (" ", Style::new()),
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{mark} "), style),
                    Span::raw(r.service.clone()),
                ]))
            })
            .collect();

        let title = if self.filtering || !self.filter.value.is_empty() {
            format!(" Services /{} ", self.filter.value)
        } else {
            " Services ".into()
        };
        let list = List::new(items)
            .block(Block::bordered().title(title))
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("▶ ");
        f.render_stateful_widget(list, area, &mut self.list);

        if self.filtering {
            let prefix = " Services /".chars().count() as u16;
            let x = area.x + 1 + prefix - 1 + self.filter.cursor as u16;
            f.set_cursor_position((x.min(area.right().saturating_sub(2)), area.y));
        }
    }

    fn draw_detail(&self, f: &mut Frame, area: Rect) {
        let block = Block::bordered().title(" Details ");
        let Some(row) = self.selected() else {
            let msg = if self.rows.is_empty() {
                "No PATs recorded yet. Press n to store one."
            } else {
                "Nothing matches the filter."
            };
            f.render_widget(Paragraph::new(msg).dim().block(block), area);
            return;
        };

        let label = |s: &'static str| Span::styled(format!("{s:<12}"), Style::new().dim());
        let warn = |s: String| Span::styled(s, Style::new().fg(Color::Yellow));
        let bad = |s: String| Span::styled(s, Style::new().fg(Color::Red));

        let mut lines = vec![Line::from(vec![
            label("service"),
            row.service.clone().bold(),
        ])];
        if let Ok(p) = crate::paths::token_path(&row.service) {
            lines.push(Line::from(vec![
                label("path"),
                p.display().to_string().into(),
            ]));
        }
        lines.push(Line::from(vec![
            label("file"),
            match row.file {
                FileState::Missing => bad("MISSING — press r to store it".into()),
                FileState::Plaintext if self.sealed => warn("plaintext — press V to seal".into()),
                FileState::Plaintext => "plaintext".into(),
                FileState::Sealed => Span::styled("sealed", Style::new().fg(Color::Green)),
            },
        ]));

        match &row.entry {
            None => {
                lines.push(Line::default());
                lines.push(Line::from(warn(
                    "No manifest entry. Press e to describe it.".into(),
                )));
            }
            Some(e) => {
                lines.push(Line::from(vec![
                    label("description"),
                    e.description.clone().into(),
                ]));
                lines.push(Line::from(vec![
                    label("username"),
                    e.username.clone().unwrap_or_else(|| "-".into()).into(),
                ]));
                lines.push(Line::from(vec![
                    label("hosts"),
                    if e.hosts.is_empty() {
                        warn("none pinned — any URL may receive it".into())
                    } else {
                        e.hosts.join(", ").into()
                    },
                ]));
                lines.push(Line::from(vec![
                    label("exec"),
                    if e.allow_exec {
                        "allowed"
                    } else {
                        "not allowed"
                    }
                    .into(),
                ]));
                if self.sealed {
                    lines.push(Line::from(vec![
                        label("approval"),
                        match e.approval {
                            Approval::Session => "session (an open unlock session is enough)",
                            Approval::Request => "request (every use is approved on its own)",
                        }
                        .into(),
                    ]));
                    lines.push(Line::from(vec![
                        label("policy"),
                        if e.policy_seal.is_some() {
                            Span::styled("signed", Style::new().fg(Color::Green))
                        } else {
                            bad("NOT SIGNED — press s to sign".into())
                        },
                    ]));
                }
                lines.push(Line::from(vec![label("updated"), e.updated.clone().into()]));
            }
        }

        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(block),
            area,
        );
    }
}

fn popup(f: &mut Frame, width: u16, height: u16) -> Rect {
    let area = f
        .area()
        .centered(Constraint::Length(width), Constraint::Length(height));
    f.render_widget(Clear, area);
    area
}

fn draw_form(f: &mut Frame, form: &Form) {
    let extra = usize::from(form.note.is_some()) + usize::from(form.error.is_some());
    let height = (form.fields.len() * 2 + extra + 2) as u16;
    let area = popup(f, 72, height);
    let block = Block::bordered()
        .title(form.title.clone())
        .title_bottom(" Tab next · Enter submit · Esc cancel ".dim());
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = Vec::new();
    let mut cursor = None;
    for (i, field) in form.fields.iter().enumerate() {
        let focused = i == form.focus;
        let label_style = if focused {
            Style::new().fg(Color::Cyan).bold()
        } else {
            Style::new()
        };
        let label = Span::styled(format!("{:<12} ", field.label), label_style);
        let value: Span = match &field.kind {
            FieldKind::Text(input) => {
                if focused {
                    cursor = Some((
                        inner.x + 13 + input.cursor as u16,
                        inner.y + lines.len() as u16,
                    ));
                }
                input.value.clone().into()
            }
            FieldKind::Toggle(b) => if *b { "[x] yes" } else { "[ ] no" }.into(),
            FieldKind::Approval(a) => match a {
                Approval::Session => "< session >",
                Approval::Request => "< request >",
            }
            .into(),
        };
        lines.push(Line::from(vec![label, value]));
        lines.push(Line::from(format!("{:13}{}", "", field.hint).dim()));
    }
    if let Some(note) = form.note {
        lines.push(Line::from(note.italic()));
    }
    if let Some(err) = &form.error {
        lines.push(Line::from(Span::styled(
            err.clone(),
            Style::new().fg(Color::Red),
        )));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    if let Some((x, y)) = cursor {
        f.set_cursor_position((x.min(inner.right().saturating_sub(1)), y));
    }
}

fn draw_confirm(f: &mut Frame, service: &str, input: &Input) {
    let area = popup(f, 64, 7);
    let block = Block::bordered()
        .title(format!(" Delete {service} "))
        .border_style(Style::new().fg(Color::Red));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let lines = vec![
        Line::from("This removes the token file and its manifest entry."),
        Line::from("It cannot be undone, and it does not revoke the token —"),
        Line::from("revoke it at the issuing service too."),
        Line::default(),
        Line::from(vec![
            "Type the service name to confirm: ".into(),
            input.value.clone().bold(),
        ]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
    f.set_cursor_position((inner.x + 34 + input.cursor as u16, inner.y + 4));
}

fn draw_help(f: &mut Frame) {
    let rows: &[(&str, &str)] = &[
        ("↑↓ j k g G", "move"),
        ("/", "filter by name, description, username"),
        (
            "Enter e",
            "edit description, username, hosts, exec, approval",
        ),
        ("n", "store a new token"),
        ("r", "rotate the selected token"),
        ("x Del", "delete the selected token"),
        ("s", "re-sign the selected policy (sealed vault)"),
        ("m", "migrate a legacy ~/.<service>_pat file"),
        ("u / l", "unlock / lock the session (sealed vault)"),
        ("V", "vault init, or seal plaintext files"),
        ("f", "fix permissions"),
        ("D o S", "doctor · orphans · status"),
        ("R", "reload from disk"),
        ("q Esc", "quit"),
    ];
    let mut lines: Vec<Line> = rows
        .iter()
        .map(|(k, v)| Line::from(vec![format!(" {k:<11}").bold().cyan(), (*v).into()]))
        .collect();
    lines.push(Line::default());
    lines.push(Line::from(
        " List markers:  ! file missing  ? no manifest entry  ~ hosts unpinned".dim(),
    ));
    lines.push(Line::from(
        " Token values are never shown; prompts run on the plain terminal.".dim(),
    ));
    let area = popup(f, 76, lines.len() as u16 + 2);
    f.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(" Keys ")
                .title_bottom(" any key closes ".dim()),
        ),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            description: "GitHub".into(),
            username: Some("me".into()),
            hosts: vec!["api.github.com".into()],
            allow_exec: false,
            approval: Approval::Session,
            policy_seal: None,
            updated: "2026-01-01".into(),
            extra: Default::default(),
        }
    }

    #[test]
    fn unchanged_form_touches_only_the_description() {
        let e = entry();
        let edits = edits_from(
            Some(&e),
            "GitHub",
            "me",
            "api.github.com",
            false,
            Some(Approval::Session),
        );
        assert_eq!(edits.description.as_deref(), Some("GitHub"));
        assert!(edits.username.is_none() && !edits.clear_username);
        assert!(edits.hosts.is_empty() && !edits.clear_hosts);
        assert!(edits.allow_exec.is_none());
        assert!(edits.approval.is_none());
    }

    #[test]
    fn emptied_fields_clear() {
        let e = entry();
        let edits = edits_from(Some(&e), "GitHub", "", "", false, None);
        assert!(edits.clear_username);
        assert!(edits.clear_hosts);
    }

    #[test]
    fn changes_are_passed_through() {
        let e = entry();
        let edits = edits_from(
            Some(&e),
            "GitHub",
            "you",
            "api.github.com, *.githubusercontent.com",
            true,
            Some(Approval::Request),
        );
        assert_eq!(edits.username.as_deref(), Some("you"));
        assert_eq!(
            edits.hosts,
            vec!["api.github.com", "*.githubusercontent.com"]
        );
        assert_eq!(edits.allow_exec, Some(true));
        assert_eq!(edits.approval, Some(Approval::Request));
    }

    #[test]
    fn hosts_split_on_commas_and_spaces() {
        assert_eq!(
            parse_hosts(" a.com,b.com  c.com ,"),
            vec!["a.com", "b.com", "c.com"]
        );
    }

    #[test]
    fn input_edits_by_char_not_byte() {
        let mut i = Input::new("héllo");
        i.handle(KeyEvent::from(KeyCode::Left));
        i.handle(KeyEvent::from(KeyCode::Backspace));
        assert_eq!(i.value, "hélo");
        i.handle(KeyEvent::from(KeyCode::Home));
        i.handle(KeyEvent::from(KeyCode::Char('x')));
        assert_eq!(i.value, "xhélo");
    }
}
