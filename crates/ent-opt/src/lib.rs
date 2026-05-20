use ent_core::{Certificate, VerificationReport};
use ent_kernel::verify;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq)]
pub struct RewriteProof {
    pub name: String,
    pub before: Certificate,
    pub after: Certificate,
    pub verification: VerificationReport,
}

#[derive(Debug, Error)]
pub enum OptimizerError {
    #[error("trusted kernel rejected optimizer output: {0}")]
    Kernel(#[from] ent_kernel::KernelError),
}

pub fn canonicalize_certificate(cert: &Certificate) -> Result<RewriteProof, OptimizerError> {
    verify(cert)?;
    let mut after = cert.clone();

    after.dimensions.sort();
    after.program_states.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.sort.cmp(&right.sort))
    });
    after.relation_names.sort();
    after
        .relations
        .sort_by(|left, right| left.label.cmp(&right.label));
    for relation in &mut after.relations {
        relation.pairs.sort();
    }
    after
        .invariants
        .sort_by(|left, right| left.name.cmp(&right.name));
    after.resources.sort_by(|left, right| {
        left.state
            .cmp(&right.state)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.owner.cmp(&right.owner))
    });
    after
        .probabilities
        .sort_by(|left, right| left.name.cmp(&right.name));
    for probability in &mut after.probabilities {
        probability
            .weights
            .sort_by(|left, right| left.0.cmp(&right.0));
    }
    after
        .ad
        .sort_by(|left, right| left.primal.cmp(&right.primal));
    after
        .backends
        .sort_by(|left, right| left.node.cmp(&right.node));
    after.external_capabilities.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.interface.cmp(&right.interface))
            .then_with(|| left.resource.cmp(&right.resource))
    });
    after
        .workspaces
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .parsers
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .selections
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .transforms
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .validators
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .objectives
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .milestones
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .tasks
        .sort_by(|left, right| left.name.cmp(&right.name));
    for task in &mut after.tasks {
        task.requires.sort();
        task.outputs.sort();
    }
    after
        .gates
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .decisions
        .sort_by(|left, right| left.name.cmp(&right.name));
    for decision in &mut after.decisions {
        decision.alternatives.sort();
    }
    after
        .notes
        .sort_by(|left, right| left.name.cmp(&right.name));
    for note in &mut after.notes {
        note.tags.sort();
    }
    after
        .lanes
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .claims
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .handoffs
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .syncs
        .sort_by(|left, right| left.name.cmp(&right.name));
    for sync in &mut after.syncs {
        sync.checks.sort();
    }
    after
        .checkpoints
        .sort_by(|left, right| left.name.cmp(&right.name));
    for checkpoint in &mut after.checkpoints {
        checkpoint.blockers.sort();
        checkpoint.next.sort();
    }
    after
        .runtime_ledgers
        .sort_by(|left, right| left.name.cmp(&right.name));
    for ledger in &mut after.runtime_ledgers {
        ledger.fields.sort();
    }
    after
        .runtime_policies
        .sort_by(|left, right| left.name.cmp(&right.name));
    for policy in &mut after.runtime_policies {
        policy.allow.sort();
        policy.deny.sort();
    }
    after
        .runtime_sessions
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .runtime_tools
        .sort_by(|left, right| left.name.cmp(&right.name));
    for tool in &mut after.runtime_tools {
        tool.reads.sort();
        tool.writes.sort();
    }
    after
        .runtime_turns
        .sort_by(|left, right| left.name.cmp(&right.name));
    for turn in &mut after.runtime_turns {
        turn.tools.sort();
    }
    after
        .runtime_hooks
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .runtime_bridges
        .sort_by(|left, right| left.name.cmp(&right.name));
    for bridge in &mut after.runtime_bridges {
        bridge.exposes.sort();
    }
    after
        .graphics
        .sort_by(|left, right| left.name.cmp(&right.name));
    for graphics in &mut after.graphics {
        graphics.imports.sort();
    }
    after
        .render_targets
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .render_pipelines
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .benchmarks
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .tensors
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .accelerators
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .datasets
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .models
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .trainings
        .sort_by(|left, right| left.name.cmp(&right.name));
    after
        .canonicals
        .sort_by(|left, right| left.name.cmp(&right.name));
    for canonical in &mut after.canonicals {
        canonical.fields.sort();
    }
    after
        .artifacts
        .sort_by(|left, right| left.name.cmp(&right.name));
    for artifact in &mut after.artifacts {
        artifact.tensors.sort();
    }
    after
        .lowerings
        .sort_by(|left, right| left.name.cmp(&right.name));
    for lowering in &mut after.lowerings {
        lowering.mappings.sort();
    }
    after
        .executors
        .sort_by(|left, right| left.name.cmp(&right.name));
    for executor in &mut after.executors {
        executor.read_artifacts.sort();
        executor.write_paths.sort();
    }
    after
        .witnesses
        .sort_by(|left, right| left.name.cmp(&right.name));
    for witness in &mut after.witnesses {
        witness.requirements.sort();
    }
    after.machines.sort_by(|left, right| left.id.cmp(&right.id));
    after
        .memory
        .sort_by(|left, right| left.name.cmp(&right.name));
    for memory in &mut after.memory {
        memory
            .regions
            .sort_by(|left, right| left.name.cmp(&right.name));
        for region in &mut memory.regions {
            region.permissions.sort();
        }
        memory.frame_conditions.sort();
    }
    after
        .instructions
        .sort_by(|left, right| left.name.cmp(&right.name));
    for instruction in &mut after.instructions {
        instruction.effects.sort();
    }
    after.abis.sort_by(|left, right| left.name.cmp(&right.name));
    after
        .proof_artifacts
        .sort_by(|left, right| left.name.cmp(&right.name));
    for artifact in &mut after.proof_artifacts {
        artifact.obligations.sort();
    }
    after
        .proofs
        .sort_by(|left, right| left.name.cmp(&right.name));

    let verification = verify(&after)?;
    Ok(RewriteProof {
        name: "canonicalize-certificate-v9".to_owned(),
        before: cert.clone(),
        after,
        verification,
    })
}

pub fn canonical_noop_rewrite(cert: &Certificate) -> Result<RewriteProof, OptimizerError> {
    canonicalize_certificate(cert)
}
