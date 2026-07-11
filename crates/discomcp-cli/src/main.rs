use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use discomcp_core::artifacts::regenerate_skill;
use discomcp_core::engine::{ProfilePlan, RefreshResult};
use discomcp_core::model::{ExplorationMode, ProfileOptions, RiskClass};
use discomcp_core::{DiscoMcp, DiscoMcpConfig, Result};

#[derive(Debug, Parser)]
#[command(
    name = "discomcp",
    version,
    about = "Safely profile unknown MCP connections into reusable operational skills"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect cached target declarations without executing target tools.
    Inspect {
        target: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Produce the first safety-validated candidate probe without executing it.
    Plan {
        target: String,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        goal: Option<String>,
        #[arg(long, value_enum, default_value_t = ModeArg::Standard)]
        mode: ModeArg,
    },
    /// Run static discovery, bounded safe profiling, and artifact generation.
    Profile {
        target: String,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        goal: Option<String>,
        #[arg(long, value_enum, default_value_t = ModeArg::Standard)]
        mode: ModeArg,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Check whether a skill already covers this target's current catalogue,
    /// without exploring or spending any reasoning calls.
    Lookup {
        target: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Refresh a profile only when target declarations have changed.
    Refresh {
        target: String,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Regenerate SKILL.md from canonical profile artifacts.
    GenerateSkill {
        target: String,
        #[arg(long)]
        profile: PathBuf,
    },
    /// Show the stable public MCP server surface reserved by this vertical slice.
    Serve {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum ModeArg {
    Quick,
    #[default]
    Standard,
    Deep,
}

impl From<ModeArg> for ExplorationMode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Quick => Self::Quick,
            ModeArg::Standard => Self::Standard,
            ModeArg::Deep => Self::Deep,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.command {
        Command::Inspect { target, config } => inspect(target, config).await,
        Command::Plan {
            target,
            config,
            goal,
            mode,
        } => plan(target, config, goal, mode).await,
        Command::Profile {
            target,
            config,
            goal,
            mode,
            output,
            dry_run,
        } => profile(target, config, goal, mode, output, dry_run).await,
        Command::Lookup { target, config } => lookup(target, config).await,
        Command::Refresh {
            target,
            config,
            output,
        } => refresh(target, config, output).await,
        Command::GenerateSkill { target, profile } => generate_skill(target, profile),
        Command::Serve { config } => serve(config),
    }
}

async fn inspect(target: String, config_path: Option<PathBuf>) -> Result<()> {
    let discomcp = DiscoMcp::new(load_config(config_path)?);
    let inspection = discomcp.inspect(&target).await?;
    println!("Target: {}", inspection.target_id);
    println!("Server: {}", inspection.server_name);
    println!("Tools discovered: {}", inspection.tools);
    println!("Resources discovered: {}", inspection.resources);
    println!("Prompts discovered: {}", inspection.prompts);
    println!(
        "Catalogue fingerprint: {}",
        inspection.catalogue_fingerprint
    );
    for (risk, count) in risk_counts(&inspection.tool_cards) {
        println!("- {risk}: {count}");
    }
    Ok(())
}

async fn plan(
    target: String,
    config_path: Option<PathBuf>,
    goal: Option<String>,
    mode: ModeArg,
) -> Result<()> {
    let config = load_config(config_path)?;
    let options = profile_options(goal, mode, None, true, &config);
    let plan = DiscoMcp::new(config).plan(&target, options).await?;
    print_plan(&plan);
    Ok(())
}

async fn profile(
    target: String,
    config_path: Option<PathBuf>,
    goal: Option<String>,
    mode: ModeArg,
    output: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let config = load_config(config_path)?;
    let options = profile_options(goal, mode, output, dry_run, &config);
    let result = DiscoMcp::new(config).profile(&target, options).await?;
    let profile = result.profile;
    let executed = profile
        .probe_log
        .iter()
        .filter(|record| {
            record.runtime_decision.outcome == discomcp_core::model::RuntimeOutcome::Accepted
        })
        .count();
    let skipped = profile.probe_log.len().saturating_sub(executed);
    println!("Target: {}", target);
    println!("Transport: configured target registry");
    println!("Tools discovered: {}", profile.catalogue.tools.len());
    println!(
        "Resources discovered: {}",
        profile.catalogue.resources.len()
    );
    println!("Prompts discovered: {}", profile.catalogue.prompts.len());
    println!(
        "Documentation sources: {}",
        profile.documentation.sources.len()
    );
    println!("Tool profile:");
    for (risk, count) in risk_counts(
        &profile
            .catalogue
            .tools
            .iter()
            .map(|tool| tool.card.clone())
            .collect::<Vec<_>>(),
    ) {
        println!("- {risk}: {count}");
    }
    println!("Exploration:");
    println!("- Probes planned: {}", profile.probe_log.len());
    println!("- Probes executed: {executed}");
    println!("- Probes skipped or rejected: {skipped}");
    println!(
        "- Structures discovered: {}",
        profile.workspace_model.structures.len()
    );
    println!(
        "- Relationships inferred: {}",
        profile.workspace_model.relationships.len()
    );
    println!(
        "- Important uncertainties: {}",
        profile.workspace_model.uncertainties.len()
    );
    println!("Generated: {}", result.output_dir.display());
    println!("- workspace-model.json");
    println!("- operational-model.json");
    println!("- SKILL.md");
    println!("- AGENTS.md");
    println!("- evals.yml");
    Ok(())
}

async fn lookup(target: String, config_path: Option<PathBuf>) -> Result<()> {
    let discomcp = DiscoMcp::new(load_config(config_path)?);
    let found = discomcp.lookup(&target).await?;
    println!("Target: {}", found.target_id);
    println!("Catalogue fingerprint: {}", found.catalogue_fingerprint);
    match found.existing_skill_dir {
        Some(dir) => println!("Existing skill found: {}", dir.display()),
        None => {
            println!("No existing skill matches this catalogue; run `profile` to generate one.")
        }
    }
    Ok(())
}

async fn refresh(
    target: String,
    config_path: Option<PathBuf>,
    output: Option<PathBuf>,
) -> Result<()> {
    let config = load_config(config_path)?;
    let options = ProfileOptions {
        output_dir: output,
        privacy_mode: config.profiles.privacy_mode.clone(),
        ..ProfileOptions::default()
    };
    let result = DiscoMcp::new(config).refresh(&target, options).await?;
    print_refresh(&result);
    Ok(())
}

fn generate_skill(target: String, profile: PathBuf) -> Result<()> {
    let output = regenerate_skill(&profile)?;
    println!(
        "Regenerated SKILL.md for target `{target}`: {}",
        output.display()
    );
    Ok(())
}

fn serve(config_path: Option<PathBuf>) -> Result<()> {
    let config = load_config(config_path)?;
    let server = discomcp_server::DiscoMcpServer::new(config);
    let surface = discomcp_server::DiscoMcpServer::tool_surface();
    println!(
        "DiscoMCP public MCP surface: {} {}",
        surface.server_name, surface.version
    );
    for tool in surface.tools {
        println!("- {}: {}", tool.name, tool.description);
    }
    let _ = server;
    println!("Protocol transport is not implemented in this first vertical slice.");
    Ok(())
}

fn load_config(path: Option<PathBuf>) -> Result<DiscoMcpConfig> {
    path.map_or_else(
        || Ok(DiscoMcpConfig::builtin_mock()),
        DiscoMcpConfig::from_file,
    )
}

fn profile_options(
    goal: Option<String>,
    mode: ModeArg,
    output_dir: Option<PathBuf>,
    dry_run: bool,
    config: &DiscoMcpConfig,
) -> ProfileOptions {
    ProfileOptions {
        mode: mode.into(),
        goal,
        output_dir,
        dry_run,
        privacy_mode: config.profiles.privacy_mode.clone(),
        budgets: None,
    }
}

fn risk_counts(cards: &[discomcp_core::model::ToolCard]) -> Vec<(&'static str, usize)> {
    let risks = [
        (RiskClass::SafeRead, "Safe reads"),
        (RiskClass::ConstrainedRead, "Constrained reads"),
        (RiskClass::SensitiveRead, "Sensitive reads"),
        (RiskClass::PureComputation, "Pure computation"),
        (RiskClass::Mutation, "Mutations"),
        (RiskClass::ExternalSideEffect, "External side effects"),
        (RiskClass::Destructive, "Destructive"),
        (RiskClass::Administrative, "Administrative"),
        (RiskClass::ArbitraryExecution, "Arbitrary execution"),
        (RiskClass::Unknown, "Unknown"),
    ];
    risks
        .into_iter()
        .filter_map(|(risk, label)| {
            let count = cards.iter().filter(|card| card.risk == risk).count();
            (count > 0).then_some((label, count))
        })
        .collect()
}

fn print_plan(plan: &ProfilePlan) {
    println!("Target: {}", plan.target_id);
    println!("Candidate tools:");
    for candidate in &plan.candidate_tools {
        println!("- {} ({:?})", candidate.name, candidate.risk);
    }
    println!(
        "Selected probe: {}",
        plan.decision.selected_tool.as_deref().unwrap_or("<stop>")
    );
    println!("Arguments: {}", plan.decision.arguments);
    println!(
        "Risk decision: {:?} - {}",
        plan.runtime_decision.outcome, plan.runtime_decision.reason
    );
    println!("Identifier provenance:");
    if plan.decision.argument_provenance.is_empty() {
        println!("- none required for this candidate");
    } else {
        for provenance in &plan.decision.argument_provenance {
            println!("- {}: {:?}", provenance.json_pointer, provenance.source);
        }
    }
    println!(
        "Budget impact: up to {} MCP probes, {} reasoning cycles, {} samples per structure.",
        plan.budgets.max_mcp_probes,
        plan.budgets.max_reasoning_cycles,
        plan.budgets.max_samples_per_structure
    );
}

fn print_refresh(result: &RefreshResult) {
    println!("Refresh changed profile: {}", result.changed);
    println!("{}", result.message);
    println!("Profile directory: {}", result.output_dir.display());
}

fn init_tracing() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "discomcp_core=info".to_string());
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
