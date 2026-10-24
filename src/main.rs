//! patman — manage personal access token files under `$HOME/.pat/`.
//!
//! The design rule the whole tool exists to enforce: a token value can move from
//! the terminal to a file, and from that file into a request, and nowhere else.
//! It is never printed, never returned to a caller that formats output, and
//! never placed in a command-line argument.

#[cfg(unix)]
mod agent;
#[cfg(unix)]
mod approve;
mod cmds;
mod error;
mod guard;
mod guardrail;
mod harness;
mod hook;
mod manifest;
mod paths;
mod policy;
mod sealed;
mod secure;
mod skill;
mod token;
#[cfg(feature = "tui")]
mod tui;
mod update;
mod usage;
mod vault;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "patman",
    version = env!("PATMAN_VERSION"),
    long_version = env!("PATMAN_LONG_VERSION"),
    about = "Store, describe, look up, rotate, and use personal access tokens in $HOME/.pat/",
    long_about = "Token values live in $HOME/.pat/<service>, locked to the current user.\n\
                  Metadata lives in $HOME/.pat/manifest.json and contains no secrets, so it is \
                  safe to read and share.\n\n\
                  No subcommand ever prints a token value."
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create $HOME/.pat/ and an empty manifest, and install the patman skill
    /// for the AI coding harnesses found: ~/.claude/skills for Claude Code,
    /// ~/.agents/skills for Codex, Gemini CLI, Copilot, Cursor, and OpenCode.
    /// Safe to re-run: it also refreshes a skill left stale by an upgrade.
    Init {
        /// Install into this skills directory only (repeatable): `claude`, or
        /// `agents` (also accepted as codex, gemini, copilot, cursor, opencode).
        /// Default: each one a detected harness reads, or both with --project.
        #[arg(long = "agent", value_enum, hide_possible_values = true)]
        agents: Vec<skill::Target>,

        /// Install into a repository (DIR/.claude/skills, DIR/.agents/skills)
        /// instead of your home directory, for committing alongside the code.
        /// DIR defaults to the current directory.
        #[arg(long, value_name = "DIR", num_args = 0..=1, default_missing_value = ".")]
        project: Option<std::path::PathBuf>,

        /// Set up $HOME/.pat/ only: no skill, no guard.
        #[arg(long, conflicts_with_all = ["agents", "project"])]
        no_skill: bool,

        /// Install the skill but leave every harness's settings alone (no
        /// guard against agents reading ~/.pat/).
        #[arg(long)]
        no_guard: bool,

        /// Take the skill and the guard back out of every harness.
        #[arg(long, conflicts_with_all = ["project", "no_skill", "no_guard"])]
        remove: bool,
    },

    /// List every recorded PAT with its description. Never shows token values.
    List {
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },

    /// Show the file path and metadata for one service.
    Lookup {
        service: String,
        #[arg(long)]
        json: bool,
    },

    /// Find a PAT by what it is used for.
    Search { keyword: String },

    /// Store or rotate a token value. Prompts on the terminal with echo off.
    ///
    /// Must be run by you, in a real terminal window — Claude Code's `!` prefix
    /// has no terminal to prompt on. It refuses to run without a TTY so a token can never be typed into,
    /// or echoed by, an agent's tool call.
    Save {
        service: String,

        /// What it's for: which account/site, which scopes. Required for a new
        /// service; kept as-is when rotating.
        #[arg(short, long)]
        description: Option<String>,

        /// Account identifier for Basic auth (an email for Atlassian Cloud, a
        /// corporate ID for most self-hosted servers). Not a secret.
        #[arg(short, long)]
        username: Option<String>,

        /// Host `patman curl` may send this token to (repeatable; exact
        /// hostname or *.example.com). Unpinned tokens go to any URL — pin
        /// this so a bad or injected URL cannot exfiltrate the token.
        #[arg(long = "host")]
        hosts: Vec<String>,

        /// Read the token from stdin instead of prompting, for piping out of a
        /// password manager: `op read ... | patman save github --stdin`.
        #[arg(long)]
        stdin: bool,
    },

    /// Replace a token value, keeping the existing description. Alias of `save`.
    Rotate {
        service: String,
        #[arg(long)]
        stdin: bool,
    },

    /// Edit the description, username, or pinned hosts. Touches no secret.
    Describe {
        service: String,
        #[arg(short, long)]
        description: Option<String>,
        #[arg(short, long)]
        username: Option<String>,
        /// Drop the username (for a service that uses Bearer-only auth).
        #[arg(long, conflicts_with = "username")]
        clear_username: bool,
        /// Replace the pinned hosts (repeatable; exact hostname or
        /// *.example.com). `patman curl` refuses URLs outside this list.
        #[arg(long = "host")]
        hosts: Vec<String>,
        /// Remove all pinned hosts (returns the token to unrestricted use).
        #[arg(long, conflicts_with = "hosts")]
        clear_hosts: bool,

        /// Let `patman exec` use this token. Under a sealed vault exec is
        /// refused unless this is set: it skips host pinning and argument
        /// vetting, so it is a per-service decision rather than a default.
        #[arg(long)]
        allow_exec: bool,

        /// Withdraw `--allow-exec`.
        #[arg(long, conflicts_with = "allow_exec")]
        deny_exec: bool,

        /// Sealed vault only: `session` lets an open unlock session spend this
        /// token unattended; `request` makes every use need its own approval
        /// (Touch ID on macOS, the vault passphrase elsewhere).
        #[arg(long, value_enum)]
        approval: Option<manifest::Approval>,

        /// Re-sign this service's policy with the vault passphrase — after
        /// editing manifest.json by hand, or for an entry with no signature.
        #[arg(long)]
        sign: bool,
    },

    /// Delete a token file and its manifest entry. Requires --yes.
    Delete {
        service: String,
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,
    },

    /// Move a legacy ~/.<service>_pat file into $HOME/.pat/<service>.
    Migrate {
        service: String,
        /// Source path, if it isn't ~/.<service>_pat.
        #[arg(long)]
        from: Option<std::path::PathBuf>,
    },

    /// Report token files with no manifest entry, and entries with no file.
    Orphans,

    /// Re-apply owner-only permissions to the directory and every file in it.
    FixPerms,

    /// Full health check: permissions, manifest validity, sealing state, orphans.
    Doctor,

    /// Run curl authenticated as <service>. The token goes to curl over stdin,
    /// never into argv where other users could read it from the process table.
    ///
    /// Example: patman curl jira -- -sS "https://x.atlassian.net/rest/api/3/myself"
    Curl {
        service: String,

        /// Which auth scheme to use.
        #[arg(long, value_enum, default_value_t = cmds::Auth::Auto)]
        auth: cmds::Auth,

        /// Arguments passed through to curl, after `--`.
        #[arg(last = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Run any command with PAT_TOKEN (and PAT_USERNAME) in its environment.
    ///
    /// Example: patman exec gh -- sh -c 'GH_TOKEN=$PAT_TOKEN gh pr list'
    /// Prefer `patman curl` when the tool is curl — stdin beats env.
    Exec {
        service: String,
        #[arg(last = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Encrypt token files at rest under a passphrase.
    #[command(subcommand)]
    Vault(VaultCmd),

    /// Start an unlock session: hold the vault key in memory so `patman curl`
    /// works without a passphrase until it expires.
    ///
    /// Must be run by you, in a real terminal window — Claude Code's `!` prefix
    /// has no terminal to prompt on. This is the gate: an agent can spend a credential during a session
    /// you opened, and cannot open one itself.
    Unlock {
        /// How long the session lasts, in minutes.
        #[arg(long, default_value_t = 15)]
        minutes: u64,
    },

    /// End the unlock session now, wiping the key from memory.
    Lock,

    /// Report whether the vault is sealed, and whether a session is open.
    Status,

    /// Open the terminal UI for editing and maintenance: browse services, edit
    /// descriptions and policy, store, rotate, delete, and run the health checks.
    ///
    /// Must be run by you, in a real terminal window. Token values are never
    /// shown; anything that prompts runs on the plain terminal with echo off.
    #[cfg(feature = "tui")]
    Tui,

    /// Check for a newer patman release and, after asking, install it over
    /// this binary. The download must carry a valid minisign signature from the
    /// release key.
    Update {
        /// Only report whether a newer release exists; install nothing.
        #[arg(long)]
        check: bool,

        /// Install without asking.
        #[arg(short, long, conflicts_with = "check")]
        yes: bool,
    },

    /// The pre-tool-use guard a harness runs; installed by `patman init`.
    ///
    /// Reads the harness's tool-call JSON on stdin and refuses any call that
    /// touches ~/.pat/, in that harness's response format.
    #[command(hide = true)]
    Hook {
        #[arg(value_enum)]
        harness: harness::Harness,
    },

    /// The unlock agent itself. Started by `patman unlock`; not for direct use.
    ///
    /// Reads the vault key from stdin — never argv, which is world-readable via
    /// the process table.
    #[command(hide = true)]
    AgentServe {
        #[arg(long, default_value_t = 900)]
        ttl: u64,
    },
}

#[derive(Subcommand)]
enum VaultCmd {
    /// Set a passphrase and start sealing token files.
    Init,
    /// Encrypt every plaintext token file in place.
    Seal,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("patman: {e}");
        std::process::exit(1);
    }
}

fn run() -> error::Result<()> {
    let cli = Cli::parse();

    // The guard runs before every tool call an agent makes. It skips the
    // preflight: a failing preflight must not turn into a blocked tool call,
    // and it has no business creating ~/.pat/ either.
    if let Cmd::Hook { harness } = cli.command {
        hook::run(harness);
        return Ok(());
    }

    // Updating replaces the binary and touches nothing under ~/.pat/.
    if let Cmd::Update { check, yes } = cli.command {
        return update::run(check, yes);
    }

    // Preflight before every command, including the read-only ones: it is cheap,
    // idempotent, and means no code path can operate on an unchecked directory.
    let ctx = cmds::bootstrap()?;

    match cli.command {
        Cmd::Init {
            agents,
            project,
            no_skill,
            no_guard,
            remove,
        } => cmds::init(
            &ctx,
            cmds::InitOpts {
                agents: &agents,
                project: project.as_deref(),
                skill: !no_skill,
                guard: !no_guard,
                remove,
            },
        ),
        Cmd::Hook { .. } | Cmd::Update { .. } => unreachable!("handled before the preflight"),
        Cmd::List { json } => cmds::list(&ctx, json),
        Cmd::Lookup { service, json } => cmds::lookup(&ctx, &service, json),
        Cmd::Search { keyword } => cmds::search(&ctx, &keyword),

        Cmd::Save {
            service,
            description,
            username,
            hosts,
            stdin,
        } => cmds::save(&ctx, &service, description, username, hosts, stdin),

        Cmd::Rotate { service, stdin } => cmds::save(&ctx, &service, None, None, Vec::new(), stdin),

        Cmd::Describe {
            service,
            description,
            username,
            clear_username,
            hosts,
            clear_hosts,
            allow_exec,
            deny_exec,
            approval,
            sign,
        } => cmds::describe(
            &ctx,
            &service,
            cmds::Edits {
                description,
                username,
                clear_username,
                hosts,
                clear_hosts,
                // None means "leave it as it is" — neither flag given.
                allow_exec: match (allow_exec, deny_exec) {
                    (true, _) => Some(true),
                    (_, true) => Some(false),
                    _ => None,
                },
                approval,
                sign,
            },
        ),

        Cmd::Delete { service, yes } => cmds::delete(&ctx, &service, yes),
        Cmd::Migrate { service, from } => cmds::migrate(&ctx, &service, from),
        Cmd::Orphans => cmds::orphans(&ctx),
        Cmd::FixPerms => cmds::fix_perms(&ctx),
        Cmd::Doctor => cmds::doctor(&ctx),
        Cmd::Curl {
            service,
            auth,
            args,
        } => cmds::curl(&ctx, &service, auth, &args),
        Cmd::Exec { service, args } => cmds::exec(&ctx, &service, &args),

        Cmd::Vault(VaultCmd::Init) => cmds::vault_init(&ctx),
        Cmd::Vault(VaultCmd::Seal) => cmds::vault_seal(&ctx),
        Cmd::Unlock { minutes } => cmds::unlock(minutes.saturating_mul(60)),
        Cmd::Lock => cmds::lock(),
        Cmd::Status => cmds::status(),
        #[cfg(feature = "tui")]
        Cmd::Tui => tui::run(&ctx),

        #[cfg(unix)]
        Cmd::AgentServe { ttl } => agent::serve(ttl),
        #[cfg(not(unix))]
        Cmd::AgentServe { .. } => error::bail("the unlock agent is unix-only"),
    }
}
