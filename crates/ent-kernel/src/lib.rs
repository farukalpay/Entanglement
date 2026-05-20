use ent_core::{
    Certificate, CheckedRows, Instability, InstabilityKind, KernelFormula, Label, ResourceAccess,
    StateId, TransformTarget, VerificationReport, CERTIFICATE_SCHEMA_VERSION, MAX_MODAL_DIMENSIONS,
    MIN_CERTIFICATE_SCHEMA_VERSION,
};
use ent_proof::{
    check_proof, PrimitiveRule, ProofCheckError, ProofEnvironment, PropositionKind, RowKind,
};
use indexmap::{IndexMap, IndexSet};
use std::collections::BTreeSet;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KernelError {
    #[error("{kind:?}: {message}; evidence={evidence:?}")]
    Instability {
        kind: InstabilityKind,
        message: String,
        evidence: Vec<String>,
    },
}

type RelationSet = BTreeSet<(StateId, StateId)>;

pub fn verify(cert: &Certificate) -> Result<VerificationReport, KernelError> {
    let mut checked = CheckedRows::default();
    if cert.version < MIN_CERTIFICATE_SCHEMA_VERSION || cert.version > CERTIFICATE_SCHEMA_VERSION {
        return fail(
            InstabilityKind::UnsupportedVersion,
            "certificate version is not supported by this kernel",
            vec![cert.version.to_string()],
        );
    }
    if cert.dimensions.len() > MAX_MODAL_DIMENSIONS {
        return fail(
            InstabilityKind::BadRelation,
            "certificate declares more modal dimensions than this kernel will expand",
            vec![
                cert.dimensions.len().to_string(),
                MAX_MODAL_DIMENSIONS.to_string(),
            ],
        );
    }
    let states: IndexSet<StateId> = cert.modal_worlds.iter().cloned().collect();
    if states.len() != cert.modal_worlds.len() {
        return fail(
            InstabilityKind::UnknownReference,
            "modal world names must be unique",
            vec![cert.world.clone()],
        );
    }
    if !states.contains(&cert.root_world) {
        return fail(
            InstabilityKind::UnknownReference,
            "root modal world is not declared",
            vec![cert.root_world.to_string()],
        );
    }

    let expected_labels: IndexSet<Label> = Label::powerset(&cert.dimensions).into_iter().collect();
    let relations = relation_map(cert, &states, &expected_labels)?;
    checked.equivalence += check_equivalence(&relations, &states)?;
    checked.inclusion += check_inclusion(&relations)?;
    checked.union_composition += check_union_composition(&relations, &states)?;
    checked.modal_truth += check_modal_truth(cert, &relations, &states)?;
    checked.factors += check_factor_witnesses(cert, &relations, &states)?;

    if cert.require_coordinate_separation {
        checked.coordinate_separation += check_coordinate_separation(cert, &relations)?;
    }
    if let Some(survivors) = &cert.public_survivors {
        checked.factors += check_factor_closure(cert, &relations, survivors)?;
    }

    checked.invariants += check_invariants(cert)?;
    checked.resources += check_resources(cert, &states)?;
    checked.probabilities += check_probabilities(cert, &states)?;
    checked.ad += check_ad(cert)?;
    checked.backends += check_backends(cert)?;
    checked.external_capabilities += check_external_capabilities(cert, &states)?;
    checked.workspaces += check_workspaces(cert)?;
    checked.parsers += check_parsers(cert)?;
    checked.selections += check_selections(cert)?;
    checked.transforms += check_transforms(cert)?;
    checked.validators += check_validators(cert)?;
    checked.objectives += check_objectives(cert)?;
    checked.milestones += check_milestones(cert)?;
    checked.tasks += check_tasks(cert)?;
    checked.gates += check_gates(cert)?;
    checked.decisions += check_decisions(cert)?;
    checked.notes += check_notes(cert)?;
    checked.graphics += check_graphics(cert)?;
    checked.render_targets += check_render_targets(cert)?;
    checked.render_pipelines += check_render_pipelines(cert)?;
    checked.benchmarks += check_benchmarks(cert)?;
    checked.tensors += check_tensors(cert)?;
    checked.accelerators += check_accelerators(cert)?;
    checked.datasets += check_datasets(cert)?;
    checked.models += check_models(cert)?;
    checked.trainings += check_trainings(cert)?;
    checked.canonicals += check_canonicals(cert)?;
    checked.artifacts += check_artifacts(cert)?;
    checked.lowerings += check_lowerings(cert)?;
    checked.executors += check_executors(cert)?;
    checked.witnesses += check_witnesses(cert)?;
    checked.proof_artifacts += check_proof_artifacts(cert)?;
    checked.machines += check_machines(cert)?;
    checked.memory += check_machine_memory(cert)?;
    checked.instructions += check_instructions(cert)?;
    checked.abis += check_abis(cert)?;
    checked.proofs += check_proofs(cert)?;
    check_workspace_proof_obligations(cert)?;
    check_protocol_proof_obligations(cert)?;
    check_graphics_proof_obligations(cert)?;
    check_tensor_proof_obligations(cert)?;
    check_runtime_boundary_proof_obligations(cert)?;
    check_machine_proof_obligations(cert)?;

    let type_map = type_map(cert, &states)?;
    if !type_map
        .get(&cert.root_world)
        .is_some_and(|truths| truths.contains(&cert.formula))
    {
        return fail(
            InstabilityKind::RootFormulaMissing,
            "root formula is not present in the root type",
            vec![cert.root_world.to_string(), cert.formula.to_string()],
        );
    }

    Ok(VerificationReport {
        world: cert.world.clone(),
        checked_rows: checked,
        instabilities: vec![],
    })
}

fn relation_map(
    cert: &Certificate,
    states: &IndexSet<StateId>,
    expected_labels: &IndexSet<Label>,
) -> Result<IndexMap<Label, RelationSet>, KernelError> {
    let mut map = IndexMap::new();
    for table in &cert.relations {
        if !expected_labels.contains(&table.label) {
            return fail(
                InstabilityKind::BadRelation,
                "relation uses a label outside the declared dimension powerset",
                vec![table.label.display_name()],
            );
        }
        let mut pairs = RelationSet::new();
        for (left, right) in &table.pairs {
            if !states.contains(left) || !states.contains(right) {
                return fail(
                    InstabilityKind::UnknownReference,
                    "relation pair names an undeclared state",
                    vec![
                        table.label.display_name(),
                        left.to_string(),
                        right.to_string(),
                    ],
                );
            }
            pairs.insert((left.clone(), right.clone()));
        }
        map.insert(table.label.clone(), pairs);
    }
    for label in expected_labels {
        if !map.contains_key(label) {
            return fail(
                InstabilityKind::BadRelation,
                "missing relation table for declared label",
                vec![label.display_name()],
            );
        }
    }
    Ok(map)
}

fn type_map(
    cert: &Certificate,
    states: &IndexSet<StateId>,
) -> Result<IndexMap<StateId, IndexSet<KernelFormula>>, KernelError> {
    let closure: IndexSet<KernelFormula> = cert.closure.iter().cloned().collect();
    let mut map = IndexMap::new();
    for (state, formulas) in &cert.types {
        if !states.contains(state) {
            return fail(
                InstabilityKind::UnknownReference,
                "type row names an undeclared state",
                vec![state.to_string()],
            );
        }
        let mut set = IndexSet::new();
        for formula in formulas {
            if !closure.contains(formula) {
                return fail(
                    InstabilityKind::ModalTruthMismatch,
                    "type row contains a formula outside closure",
                    vec![state.to_string(), formula.to_string()],
                );
            }
            set.insert(formula.clone());
        }
        map.insert(state.clone(), set);
    }
    for state in states {
        if !map.contains_key(state) {
            return fail(
                InstabilityKind::UnknownReference,
                "missing type row for state",
                vec![state.to_string()],
            );
        }
    }
    Ok(map)
}

fn check_equivalence(
    relations: &IndexMap<Label, RelationSet>,
    states: &IndexSet<StateId>,
) -> Result<usize, KernelError> {
    let mut rows = 0;
    for (label, rel) in relations {
        for state in states {
            rows += 1;
            if !rel.contains(&(state.clone(), state.clone())) {
                return fail(
                    InstabilityKind::BadRelation,
                    "relation is not reflexive",
                    vec![label.display_name(), state.to_string()],
                );
            }
        }
        for (left, right) in rel {
            rows += 1;
            if !rel.contains(&(right.clone(), left.clone())) {
                return fail(
                    InstabilityKind::BadRelation,
                    "relation is not symmetric",
                    vec![label.display_name(), left.to_string(), right.to_string()],
                );
            }
        }
        for (left, mid) in rel {
            for state in states {
                rows += 1;
                if rel.contains(&(mid.clone(), state.clone()))
                    && !rel.contains(&(left.clone(), state.clone()))
                {
                    return fail(
                        InstabilityKind::BadRelation,
                        "relation is not transitive",
                        vec![
                            label.display_name(),
                            left.to_string(),
                            mid.to_string(),
                            state.to_string(),
                        ],
                    );
                }
            }
        }
    }
    if let Some(empty) = relations.get(&Label::empty()) {
        let identity: RelationSet = states
            .iter()
            .map(|state| (state.clone(), state.clone()))
            .collect();
        if empty != &identity {
            return fail(
                InstabilityKind::BadRelation,
                "empty label relation must be exactly identity",
                vec!["empty".to_owned()],
            );
        }
    }
    Ok(rows)
}

fn check_inclusion(relations: &IndexMap<Label, RelationSet>) -> Result<usize, KernelError> {
    let mut rows = 0;
    for (left_label, left_rel) in relations {
        for (right_label, right_rel) in relations {
            if left_label.is_subset_of(right_label) {
                rows += 1;
                if !left_rel.is_subset(right_rel) {
                    return fail(
                        InstabilityKind::BadRelation,
                        "label inclusion does not imply relation inclusion",
                        vec![left_label.display_name(), right_label.display_name()],
                    );
                }
            }
        }
    }
    Ok(rows)
}

fn check_union_composition(
    relations: &IndexMap<Label, RelationSet>,
    states: &IndexSet<StateId>,
) -> Result<usize, KernelError> {
    let mut rows = 0;
    for (left_label, left_rel) in relations {
        for (right_label, right_rel) in relations {
            let union = left_label.union(right_label);
            let Some(union_rel) = relations.get(&union) else {
                return fail(
                    InstabilityKind::BadRelation,
                    "missing union relation",
                    vec![union.display_name()],
                );
            };
            for from in states {
                for to in states {
                    rows += 1;
                    let composed = states.iter().any(|mid| {
                        left_rel.contains(&(from.clone(), mid.clone()))
                            && right_rel.contains(&(mid.clone(), to.clone()))
                    });
                    let direct = union_rel.contains(&(from.clone(), to.clone()));
                    if direct && !composed {
                        return fail(
                            InstabilityKind::MissingMidpoint,
                            "union edge has no factor midpoint",
                            vec![
                                left_label.display_name(),
                                right_label.display_name(),
                                from.to_string(),
                                to.to_string(),
                            ],
                        );
                    }
                    if composed && !direct {
                        return fail(
                            InstabilityKind::BadRelation,
                            "factor path has no union edge",
                            vec![
                                left_label.display_name(),
                                right_label.display_name(),
                                from.to_string(),
                                to.to_string(),
                            ],
                        );
                    }
                }
            }
        }
    }
    Ok(rows)
}

fn check_modal_truth(
    cert: &Certificate,
    relations: &IndexMap<Label, RelationSet>,
    states: &IndexSet<StateId>,
) -> Result<usize, KernelError> {
    let types = type_map(cert, states)?;
    let mut rows = 0;
    for state in states {
        let state_type = types.get(state).expect("type map already checked");
        for formula in &cert.closure {
            match formula {
                KernelFormula::Box(label, body) => {
                    rows += 1;
                    let rel = relation_for(relations, label)?;
                    let actual = states.iter().all(|target| {
                        !rel.contains(&(state.clone(), target.clone()))
                            || types
                                .get(target)
                                .is_some_and(|target_type| target_type.contains(body.as_ref()))
                    });
                    if state_type.contains(formula) != actual {
                        return fail(
                            InstabilityKind::ModalTruthMismatch,
                            "box truth row disagrees with relation table",
                            vec![state.to_string(), formula.to_string()],
                        );
                    }
                }
                KernelFormula::Diamond(label, body) => {
                    rows += 1;
                    let rel = relation_for(relations, label)?;
                    let actual = states.iter().any(|target| {
                        rel.contains(&(state.clone(), target.clone()))
                            && types
                                .get(target)
                                .is_some_and(|target_type| target_type.contains(body.as_ref()))
                    });
                    if state_type.contains(formula) != actual {
                        return fail(
                            InstabilityKind::ModalTruthMismatch,
                            "diamond truth row disagrees with relation table",
                            vec![state.to_string(), formula.to_string()],
                        );
                    }
                }
                _ => {}
            }
        }
    }
    for witness in &cert.diamonds {
        rows += 1;
        if !states.contains(&witness.state) || !states.contains(&witness.target) {
            return fail(
                InstabilityKind::DiamondWitnessInvalid,
                "diamond witness names undeclared state",
                vec![witness.state.to_string(), witness.target.to_string()],
            );
        }
        let rel = relation_for(relations, &witness.label)?;
        if !rel.contains(&(witness.state.clone(), witness.target.clone())) {
            return fail(
                InstabilityKind::DiamondWitnessInvalid,
                "diamond witness target is not a labelled successor",
                vec![
                    witness.state.to_string(),
                    witness.label.display_name(),
                    witness.target.to_string(),
                ],
            );
        }
        if !types
            .get(&witness.target)
            .is_some_and(|target_type| target_type.contains(&witness.body))
        {
            return fail(
                InstabilityKind::DiamondWitnessInvalid,
                "diamond witness target does not satisfy body",
                vec![witness.target.to_string(), witness.body.to_string()],
            );
        }
    }
    Ok(rows)
}

fn check_factor_witnesses(
    cert: &Certificate,
    relations: &IndexMap<Label, RelationSet>,
    states: &IndexSet<StateId>,
) -> Result<usize, KernelError> {
    let mut rows = 0;
    for witness in &cert.factors {
        rows += 1;
        if !states.contains(&witness.from)
            || !states.contains(&witness.midpoint)
            || !states.contains(&witness.to)
        {
            return fail(
                InstabilityKind::MissingMidpoint,
                "factor witness names undeclared state",
                vec![
                    witness.from.to_string(),
                    witness.midpoint.to_string(),
                    witness.to.to_string(),
                ],
            );
        }
        let left = relation_for(relations, &witness.left)?;
        let right = relation_for(relations, &witness.right)?;
        if !left.contains(&(witness.from.clone(), witness.midpoint.clone()))
            || !right.contains(&(witness.midpoint.clone(), witness.to.clone()))
        {
            return fail(
                InstabilityKind::MissingMidpoint,
                "factor witness does not name valid factor edges",
                vec![
                    witness.left.display_name(),
                    witness.right.display_name(),
                    witness.from.to_string(),
                    witness.midpoint.to_string(),
                    witness.to.to_string(),
                ],
            );
        }
    }
    Ok(rows)
}

fn check_coordinate_separation(
    cert: &Certificate,
    relations: &IndexMap<Label, RelationSet>,
) -> Result<usize, KernelError> {
    let mut rows = 0;
    for left in &cert.modal_worlds {
        for right in &cert.modal_worlds {
            rows += 1;
            if left == right {
                continue;
            }
            let indistinguishable = cert.dimensions.iter().all(|dimension| {
                let singleton = Label::new([dimension.clone()]);
                let complement = singleton.complement(&cert.dimensions);
                relations
                    .get(&complement)
                    .is_some_and(|rel| rel.contains(&(left.clone(), right.clone())))
            });
            if indistinguishable {
                return fail(
                    InstabilityKind::CoordinateSeparationFailure,
                    "distinct states are not separated by coordinate quotients",
                    vec![left.to_string(), right.to_string()],
                );
            }
        }
    }
    Ok(rows)
}

fn check_factor_closure(
    _cert: &Certificate,
    relations: &IndexMap<Label, RelationSet>,
    survivors: &[StateId],
) -> Result<usize, KernelError> {
    let survivor_set: IndexSet<StateId> = survivors.iter().cloned().collect();
    let mut rows = 0;
    for (left_label, left_rel) in relations {
        for (right_label, right_rel) in relations {
            let union = left_label.union(right_label);
            let union_rel = relation_for(relations, &union)?;
            for from in &survivor_set {
                for to in &survivor_set {
                    rows += 1;
                    if union_rel.contains(&(from.clone(), to.clone())) {
                        let has_surviving_midpoint = survivor_set.iter().any(|mid| {
                            left_rel.contains(&(from.clone(), mid.clone()))
                                && right_rel.contains(&(mid.clone(), to.clone()))
                        });
                        if !has_surviving_midpoint {
                            return fail(
                                InstabilityKind::FactorClosureFailure,
                                "public restriction deletes every factor midpoint",
                                vec![
                                    left_label.display_name(),
                                    right_label.display_name(),
                                    from.to_string(),
                                    to.to_string(),
                                ],
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(rows)
}

fn check_invariants(cert: &Certificate) -> Result<usize, KernelError> {
    for invariant in &cert.invariants {
        require_evidence("invariant", &invariant.name, &invariant.evidence)?;
        if (invariant.before - invariant.after).abs() > invariant.tolerance {
            return fail(
                InstabilityKind::InvariantDrift,
                "invariant is not preserved within tolerance",
                vec![
                    invariant.name.clone(),
                    invariant.before.to_string(),
                    invariant.after.to_string(),
                ],
            );
        }
    }
    Ok(cert.invariants.len())
}

fn check_resources(cert: &Certificate, states: &IndexSet<StateId>) -> Result<usize, KernelError> {
    let mut writers: IndexMap<(&StateId, &str), &str> = IndexMap::new();
    for resource in &cert.resources {
        require_evidence("resource", &resource.name, &resource.evidence)?;
        if !states.contains(&resource.state) {
            return fail(
                InstabilityKind::UnknownReference,
                "resource row names undeclared state",
                vec![resource.name.clone(), resource.state.to_string()],
            );
        }
        if resource.access == ResourceAccess::Write {
            let key = (&resource.state, resource.name.as_str());
            if let Some(existing) = writers.insert(key, resource.owner.as_str()) {
                if existing != resource.owner {
                    return fail(
                        InstabilityKind::ResourceConflict,
                        "resource has multiple writers in one state",
                        vec![
                            resource.state.to_string(),
                            resource.name.clone(),
                            existing.to_owned(),
                            resource.owner.clone(),
                        ],
                    );
                }
            }
        }
    }
    Ok(cert.resources.len())
}

fn check_probabilities(
    cert: &Certificate,
    states: &IndexSet<StateId>,
) -> Result<usize, KernelError> {
    for probability in &cert.probabilities {
        require_evidence("probability", &probability.name, &probability.evidence)?;
        if !states.contains(&probability.state) {
            return fail(
                InstabilityKind::UnknownReference,
                "probability row names undeclared state",
                vec![probability.name.clone(), probability.state.to_string()],
            );
        }
        if probability
            .weights
            .iter()
            .any(|(_, weight)| *weight < 0.0 || !weight.is_finite())
        {
            return fail(
                InstabilityKind::ProbabilityDrift,
                "probability row contains negative or non-finite mass",
                vec![probability.name.clone()],
            );
        }
        let sum: f64 = probability.weights.iter().map(|(_, weight)| *weight).sum();
        if (sum - 1.0).abs() > probability.tolerance {
            return fail(
                InstabilityKind::ProbabilityDrift,
                "probability mass does not normalize",
                vec![probability.name.clone(), sum.to_string()],
            );
        }
    }
    Ok(cert.probabilities.len())
}

fn check_ad(cert: &Certificate) -> Result<usize, KernelError> {
    for contract in &cert.ad {
        require_evidence("ad", &contract.primal, &contract.evidence)?;
        if contract.primal.is_empty()
            || contract.tangent.is_empty()
            || contract.adjoint.is_empty()
            || contract.law.is_empty()
        {
            return fail(
                InstabilityKind::AdContractViolation,
                "AD row must name primal, tangent, adjoint, and law",
                vec![contract.primal.clone()],
            );
        }
    }
    Ok(cert.ad.len())
}

fn check_backends(cert: &Certificate) -> Result<usize, KernelError> {
    for backend in &cert.backends {
        require_evidence("backend", &backend.node, &backend.evidence)?;
        if !backend.admissible {
            return fail(
                InstabilityKind::BackendInadmissible,
                "backend contract is marked inadmissible",
                vec![backend.node.clone(), backend.evidence.clone()],
            );
        }
    }
    Ok(cert.backends.len())
}

fn check_external_capabilities(
    cert: &Certificate,
    states: &IndexSet<StateId>,
) -> Result<usize, KernelError> {
    let declared_program_states: IndexSet<&str> = cert
        .program_states
        .iter()
        .map(|state| state.name.as_str())
        .collect();
    let mut names = IndexSet::new();
    let mut writers: IndexMap<(&StateId, &str), &str> = IndexMap::new();
    for resource in &cert.resources {
        if resource.access == ResourceAccess::Write {
            writers.insert(
                (&resource.state, resource.name.as_str()),
                resource.owner.as_str(),
            );
        }
    }

    for external in &cert.external_capabilities {
        require_evidence("external", &external.name, &external.evidence)?;
        if !names.insert(external.name.as_str()) {
            return fail(
                InstabilityKind::ExternalInadmissible,
                "external capability names must be unique",
                vec![external.name.clone()],
            );
        }
        if external.name.is_empty() || external.interface.is_empty() || external.resource.is_empty()
        {
            return fail(
                InstabilityKind::ExternalInadmissible,
                "external capability must name boundary, interface, and resource",
                vec![external.name.clone()],
            );
        }
        if !states.contains(&external.state) {
            return fail(
                InstabilityKind::UnknownReference,
                "external capability names undeclared modal world",
                vec![external.name.clone(), external.state.to_string()],
            );
        }
        if !declared_program_states.contains(external.resource.as_str()) {
            return fail(
                InstabilityKind::UnknownReference,
                "external capability references undeclared program state/resource",
                vec![external.name.clone(), external.resource.clone()],
            );
        }
        if !external.admissible {
            return fail(
                InstabilityKind::ExternalInadmissible,
                "external capability is marked inadmissible",
                vec![external.name.clone(), external.evidence.clone()],
            );
        }
        if external.access == ResourceAccess::Write {
            let key = (&external.state, external.resource.as_str());
            if let Some(existing) = writers.insert(key, external.name.as_str()) {
                if existing != external.name {
                    return fail(
                        InstabilityKind::ResourceConflict,
                        "external capability writes a resource owned by another writer",
                        vec![
                            external.state.to_string(),
                            external.resource.clone(),
                            existing.to_owned(),
                            external.name.clone(),
                        ],
                    );
                }
            }
        }
    }
    Ok(cert.external_capabilities.len())
}

fn check_workspaces(cert: &Certificate) -> Result<usize, KernelError> {
    let mut names = IndexSet::new();
    for workspace in &cert.workspaces {
        require_evidence("workspace", &workspace.name, &workspace.evidence)?;
        if !names.insert(workspace.name.as_str()) {
            return fail(
                InstabilityKind::WorkspaceInadmissible,
                "workspace names must be unique",
                vec![workspace.name.clone()],
            );
        }
        if workspace.name.is_empty() || workspace.boundary != "filesystem" {
            return fail(
                InstabilityKind::WorkspaceInadmissible,
                "workspace must name an explicit filesystem boundary",
                vec![workspace.name.clone(), workspace.boundary.clone()],
            );
        }
    }
    Ok(cert.workspaces.len())
}

fn check_parsers(cert: &Certificate) -> Result<usize, KernelError> {
    let mut names = IndexSet::new();
    for parser in &cert.parsers {
        require_evidence("parser", &parser.name, &parser.evidence)?;
        if !names.insert(parser.name.as_str()) {
            return fail(
                InstabilityKind::ParserInadmissible,
                "parser adapter names must be unique",
                vec![parser.name.clone()],
            );
        }
        if !supported_parser_adapter(&parser.language, &parser.adapter) {
            return fail(
                InstabilityKind::ParserInadmissible,
                "parser adapter is not registered in the trusted adapter registry",
                vec![
                    parser.name.clone(),
                    parser.language.clone(),
                    parser.adapter.clone(),
                ],
            );
        }
    }
    Ok(cert.parsers.len())
}

fn check_selections(cert: &Certificate) -> Result<usize, KernelError> {
    let parser_names: IndexSet<&str> = cert
        .parsers
        .iter()
        .map(|parser| parser.name.as_str())
        .collect();
    let mut names = IndexSet::new();
    for selection in &cert.selections {
        require_evidence("selection", &selection.name, &selection.evidence)?;
        if !names.insert(selection.name.as_str()) {
            return fail(
                InstabilityKind::SelectionInadmissible,
                "selection names must be unique",
                vec![selection.name.clone()],
            );
        }
        if selection.predicate.trim().is_empty() {
            return fail(
                InstabilityKind::SelectionInadmissible,
                "selection predicate must be explicit",
                vec![selection.name.clone()],
            );
        }
        for parser_name in parsed_by_predicate(&selection.predicate)? {
            if !parser_names.contains(parser_name.as_str()) {
                return fail(
                    InstabilityKind::UnknownReference,
                    "selection references an undeclared parser adapter",
                    vec![selection.name.clone(), parser_name],
                );
            }
        }
    }
    Ok(cert.selections.len())
}

fn check_transforms(cert: &Certificate) -> Result<usize, KernelError> {
    let selection_names: IndexSet<&str> = cert
        .selections
        .iter()
        .map(|selection| selection.name.as_str())
        .collect();
    let mut names = IndexSet::new();
    let mut deleting_direct_files = IndexSet::new();
    for transform in &cert.transforms {
        require_evidence("transform", &transform.name, &transform.evidence)?;
        if !names.insert(transform.name.as_str()) {
            return fail(
                InstabilityKind::TransformInadmissible,
                "transform names must be unique",
                vec![transform.name.clone()],
            );
        }
        match &transform.target {
            TransformTarget::Selection(selection) => {
                if !selection_names.contains(selection.as_str()) {
                    return fail(
                        InstabilityKind::UnknownReference,
                        "transform references an undeclared selection",
                        vec![transform.name.clone(), selection.clone()],
                    );
                }
            }
            TransformTarget::File(path) if path.trim().is_empty() => {
                return fail(
                    InstabilityKind::TransformInadmissible,
                    "file transform target must be explicit",
                    vec![transform.name.clone()],
                );
            }
            TransformTarget::File(path) => {
                if transform.operation == "delete_files" {
                    deleting_direct_files.insert(path.as_str());
                } else if deleting_direct_files.contains(path.as_str()) {
                    return fail(
                        InstabilityKind::TransformInadmissible,
                        "direct file transform writes a file already marked for deletion",
                        vec![transform.name.clone(), path.clone()],
                    );
                }
            }
        }
        check_transform_shape(transform)?;
    }
    Ok(cert.transforms.len())
}

fn check_transform_shape(transform: &ent_core::TransformContract) -> Result<(), KernelError> {
    match transform.operation.as_str() {
        "remove_comments" => {
            if !matches!(transform.target, TransformTarget::Selection(_))
                || transform.destination.is_some()
                || transform.predicate.is_some()
                || transform.replacement.is_some()
            {
                return invalid_transform(
                    transform,
                    "remove_comments requires only a selection target",
                );
            }
        }
        "flatten_modules" => {
            if !matches!(transform.target, TransformTarget::Selection(_))
                || transform.destination.as_deref().is_none_or(str::is_empty)
                || transform.predicate.is_some()
                || transform.replacement.is_some()
            {
                return invalid_transform(
                    transform,
                    "flatten_modules requires a selection target and destination",
                );
            }
        }
        "flatten_files" => {
            if !matches!(transform.target, TransformTarget::Selection(_))
                || transform.destination.as_deref().is_none_or(str::is_empty)
                || transform.predicate.is_some()
                || transform.replacement.is_some()
            {
                return invalid_transform(
                    transform,
                    "flatten_files requires a selection target and destination",
                );
            }
        }
        "delete_files" => {
            if transform.destination.is_some()
                || transform.predicate.is_some()
                || transform.replacement.is_some()
            {
                return invalid_transform(transform, "delete_files does not accept clauses");
            }
        }
        "delete_lines" => {
            if !matches!(transform.target, TransformTarget::File(_))
                || transform.destination.is_some()
                || transform.predicate.as_deref().is_none_or(str::is_empty)
                || transform.replacement.is_some()
            {
                return invalid_transform(
                    transform,
                    "delete_lines requires a file target and predicate",
                );
            }
        }
        "replace_text" | "replace_word" => {
            if transform.destination.is_some()
                || transform.predicate.is_some()
                || transform.replacement.is_none()
            {
                return invalid_transform(
                    transform,
                    "replacement transforms require a target plus from/to literals",
                );
            }
        }
        "rename_paths" => {
            if !matches!(transform.target, TransformTarget::Selection(_))
                || transform.destination.is_some()
                || transform.predicate.is_some()
                || transform.replacement.is_none()
            {
                return invalid_transform(
                    transform,
                    "rename_paths requires a selection target plus from/to literals",
                );
            }
        }
        _ => {
            return fail(
                InstabilityKind::TransformInadmissible,
                "transform operation is not registered",
                vec![transform.name.clone(), transform.operation.clone()],
            );
        }
    }
    Ok(())
}

fn check_validators(cert: &Certificate) -> Result<usize, KernelError> {
    let mut names = IndexSet::new();
    for validator in &cert.validators {
        require_evidence("validator", &validator.name, &validator.evidence)?;
        if !names.insert(validator.name.as_str()) {
            return fail(
                InstabilityKind::ValidatorInadmissible,
                "validator names must be unique",
                vec![validator.name.clone()],
            );
        }
        if validator.argv.is_empty() || validator.argv.iter().any(|arg| arg.is_empty()) {
            return fail(
                InstabilityKind::ValidatorInadmissible,
                "validator argv must be explicit and non-empty",
                vec![validator.name.clone()],
            );
        }
    }
    Ok(cert.validators.len())
}

fn check_objectives(cert: &Certificate) -> Result<usize, KernelError> {
    let mut names = IndexSet::new();
    for objective in &cert.objectives {
        require_evidence("objective", &objective.name, &objective.evidence)?;
        if !names.insert(objective.name.as_str()) {
            return fail(
                InstabilityKind::ObjectiveInadmissible,
                "objective names must be unique",
                vec![objective.name.clone()],
            );
        }
        if !valid_identifier(&objective.name) || objective.summary.trim().is_empty() {
            return fail(
                InstabilityKind::ObjectiveInadmissible,
                "objective must have a stable name and summary",
                vec![objective.name.clone()],
            );
        }
        if !matches!(
            objective.priority.as_str(),
            "low" | "medium" | "high" | "critical"
        ) {
            return fail(
                InstabilityKind::ObjectiveInadmissible,
                "objective priority is not registered",
                vec![objective.name.clone(), objective.priority.clone()],
            );
        }
    }
    Ok(cert.objectives.len())
}

fn check_milestones(cert: &Certificate) -> Result<usize, KernelError> {
    let objective_names = cert
        .objectives
        .iter()
        .map(|objective| objective.name.as_str())
        .collect::<IndexSet<_>>();
    let mut names = IndexSet::new();
    for milestone in &cert.milestones {
        require_evidence("milestone", &milestone.name, &milestone.evidence)?;
        if !names.insert(milestone.name.as_str()) {
            return fail(
                InstabilityKind::MilestoneInadmissible,
                "milestone names must be unique",
                vec![milestone.name.clone()],
            );
        }
        if !valid_identifier(&milestone.name) {
            return fail(
                InstabilityKind::MilestoneInadmissible,
                "milestone name must be stable",
                vec![milestone.name.clone()],
            );
        }
        if !objective_names.contains(milestone.objective.as_str()) {
            return fail(
                InstabilityKind::UnknownReference,
                "milestone references an undeclared objective",
                vec![milestone.name.clone(), milestone.objective.clone()],
            );
        }
        if !matches!(
            milestone.state.as_str(),
            "planned" | "active" | "blocked" | "done" | "dropped"
        ) {
            return fail(
                InstabilityKind::MilestoneInadmissible,
                "milestone state is not registered",
                vec![milestone.name.clone(), milestone.state.clone()],
            );
        }
        if !valid_due(&milestone.due) {
            return fail(
                InstabilityKind::MilestoneInadmissible,
                "milestone due value must be YYYY-MM-DD or unscheduled",
                vec![milestone.name.clone(), milestone.due.clone()],
            );
        }
    }
    Ok(cert.milestones.len())
}

fn check_tasks(cert: &Certificate) -> Result<usize, KernelError> {
    let milestone_names = cert
        .milestones
        .iter()
        .map(|milestone| milestone.name.as_str())
        .collect::<IndexSet<_>>();
    let task_names = cert
        .tasks
        .iter()
        .map(|task| task.name.as_str())
        .collect::<IndexSet<_>>();
    let mut names = IndexSet::new();
    for task in &cert.tasks {
        require_evidence("task", &task.name, &task.evidence)?;
        if !names.insert(task.name.as_str()) {
            return fail(
                InstabilityKind::TaskInadmissible,
                "task names must be unique",
                vec![task.name.clone()],
            );
        }
        if !valid_identifier(&task.name)
            || task.title.trim().is_empty()
            || task.owner.trim().is_empty()
        {
            return fail(
                InstabilityKind::TaskInadmissible,
                "task must have a stable name, title, and owner",
                vec![task.name.clone()],
            );
        }
        if !milestone_names.contains(task.milestone.as_str()) {
            return fail(
                InstabilityKind::UnknownReference,
                "task references an undeclared milestone",
                vec![task.name.clone(), task.milestone.clone()],
            );
        }
        if !matches!(
            task.kind.as_str(),
            "research"
                | "design"
                | "implement"
                | "verify"
                | "document"
                | "release"
                | "cleanup"
                | "migration"
                | "review"
        ) {
            return fail(
                InstabilityKind::TaskInadmissible,
                "task kind is not registered",
                vec![task.name.clone(), task.kind.clone()],
            );
        }
        if !matches!(
            task.state.as_str(),
            "todo" | "ready" | "active" | "blocked" | "done" | "dropped"
        ) {
            return fail(
                InstabilityKind::TaskInadmissible,
                "task state is not registered",
                vec![task.name.clone(), task.state.clone()],
            );
        }
        let mut requires = IndexSet::new();
        for dependency in &task.requires {
            if dependency == &task.name || !requires.insert(dependency.as_str()) {
                return fail(
                    InstabilityKind::TaskInadmissible,
                    "task dependency list must be unique and not self-referential",
                    vec![task.name.clone(), dependency.clone()],
                );
            }
            if !task_names.contains(dependency.as_str()) {
                return fail(
                    InstabilityKind::UnknownReference,
                    "task dependency references an undeclared task",
                    vec![task.name.clone(), dependency.clone()],
                );
            }
        }
        if task.outputs.iter().any(|output| output.trim().is_empty()) {
            return fail(
                InstabilityKind::TaskInadmissible,
                "task outputs must not contain empty entries",
                vec![task.name.clone()],
            );
        }
    }
    Ok(cert.tasks.len())
}

fn check_gates(cert: &Certificate) -> Result<usize, KernelError> {
    let task_names = cert
        .tasks
        .iter()
        .map(|task| task.name.as_str())
        .collect::<IndexSet<_>>();
    let validator_names = cert
        .validators
        .iter()
        .map(|validator| validator.name.as_str())
        .collect::<IndexSet<_>>();
    let transform_names = cert
        .transforms
        .iter()
        .map(|transform| transform.name.as_str())
        .collect::<IndexSet<_>>();
    let mut names = IndexSet::new();
    for gate in &cert.gates {
        require_evidence("gate", &gate.name, &gate.evidence)?;
        if !names.insert(gate.name.as_str()) {
            return fail(
                InstabilityKind::GateInadmissible,
                "gate names must be unique",
                vec![gate.name.clone()],
            );
        }
        if !valid_identifier(&gate.name) {
            return fail(
                InstabilityKind::GateInadmissible,
                "gate name must be stable",
                vec![gate.name.clone()],
            );
        }
        if !task_names.contains(gate.task.as_str()) {
            return fail(
                InstabilityKind::UnknownReference,
                "gate references an undeclared task",
                vec![gate.name.clone(), gate.task.clone()],
            );
        }
        if !valid_gate_check(&gate.check, &validator_names, &transform_names)? {
            return fail(
                InstabilityKind::GateInadmissible,
                "gate check is not registered",
                vec![gate.name.clone(), gate.check.clone()],
            );
        }
        if !matches!(
            gate.expect.as_str(),
            "pass" | "fail" | "changed" | "unchanged" | "present" | "absent" | "recorded"
        ) {
            return fail(
                InstabilityKind::GateInadmissible,
                "gate expectation is not registered",
                vec![gate.name.clone(), gate.expect.clone()],
            );
        }
    }
    Ok(cert.gates.len())
}

fn check_decisions(cert: &Certificate) -> Result<usize, KernelError> {
    let scopes = protocol_scopes(cert);
    let mut names = IndexSet::new();
    for decision in &cert.decisions {
        require_evidence("decision", &decision.name, &decision.evidence)?;
        if !names.insert(decision.name.as_str()) {
            return fail(
                InstabilityKind::DecisionInadmissible,
                "decision names must be unique",
                vec![decision.name.clone()],
            );
        }
        if !valid_identifier(&decision.name)
            || decision.choice.trim().is_empty()
            || decision.rationale.trim().is_empty()
        {
            return fail(
                InstabilityKind::DecisionInadmissible,
                "decision must have a stable name, choice, and rationale",
                vec![decision.name.clone()],
            );
        }
        if !scope_exists(&decision.scope, &scopes) {
            return fail(
                InstabilityKind::UnknownReference,
                "decision references an undeclared scope",
                vec![decision.name.clone(), decision.scope.clone()],
            );
        }
        if decision
            .alternatives
            .iter()
            .any(|alternative| alternative.trim().is_empty())
        {
            return fail(
                InstabilityKind::DecisionInadmissible,
                "decision alternatives must not contain empty entries",
                vec![decision.name.clone()],
            );
        }
    }
    Ok(cert.decisions.len())
}

fn check_notes(cert: &Certificate) -> Result<usize, KernelError> {
    let scopes = protocol_scopes(cert);
    let mut names = IndexSet::new();
    for note in &cert.notes {
        require_evidence("note", &note.name, &note.evidence)?;
        if !names.insert(note.name.as_str()) {
            return fail(
                InstabilityKind::NoteInadmissible,
                "note names must be unique",
                vec![note.name.clone()],
            );
        }
        if !valid_identifier(&note.name) || note.text.trim().is_empty() {
            return fail(
                InstabilityKind::NoteInadmissible,
                "note must have a stable name and text",
                vec![note.name.clone()],
            );
        }
        if !scope_exists(&note.scope, &scopes) {
            return fail(
                InstabilityKind::UnknownReference,
                "note references an undeclared scope",
                vec![note.name.clone(), note.scope.clone()],
            );
        }
        let mut tags = IndexSet::new();
        for tag in &note.tags {
            if !valid_identifier(tag) || !tags.insert(tag.as_str()) {
                return fail(
                    InstabilityKind::NoteInadmissible,
                    "note tags must be stable and unique",
                    vec![note.name.clone(), tag.clone()],
                );
            }
        }
    }
    Ok(cert.notes.len())
}

fn check_graphics(cert: &Certificate) -> Result<usize, KernelError> {
    let mut names = IndexSet::new();
    for graphics in &cert.graphics {
        require_evidence("graphics", &graphics.name, &graphics.evidence)?;
        if !names.insert(graphics.name.as_str()) {
            return fail(
                InstabilityKind::GraphicsInadmissible,
                "graphics contract names must be unique",
                vec![graphics.name.clone()],
            );
        }
        if graphics.name.is_empty()
            || graphics.entry.is_empty()
            || graphics.source_digest.is_empty()
            || !graphics.source_digest.starts_with("sha256:")
        {
            return fail(
                InstabilityKind::GraphicsInadmissible,
                "graphics contract must name entry point and sha256 source digest",
                vec![graphics.name.clone()],
            );
        }
        if graphics
            .imports
            .iter()
            .any(|import| import.is_empty() || import.contains("..") || import.starts_with('/'))
        {
            return fail(
                InstabilityKind::GraphicsInadmissible,
                "graphics imports must be explicit library-relative paths",
                vec![graphics.name.clone()],
            );
        }
    }
    Ok(cert.graphics.len())
}

fn check_render_targets(cert: &Certificate) -> Result<usize, KernelError> {
    let mut names = IndexSet::new();
    for target in &cert.render_targets {
        require_evidence("render-target", &target.name, &target.evidence)?;
        if !names.insert(target.name.as_str()) {
            return fail(
                InstabilityKind::RenderTargetInadmissible,
                "render target names must be unique",
                vec![target.name.clone()],
            );
        }
        if target.name.is_empty()
            || target.width == 0
            || target.height == 0
            || target.width > 8192
            || target.height > 8192
            || !matches!(target.format.as_str(), "rgba8" | "rgb8")
        {
            return fail(
                InstabilityKind::RenderTargetInadmissible,
                "render target must declare bounded dimensions and a registered pixel format",
                vec![
                    target.name.clone(),
                    target.width.to_string(),
                    target.height.to_string(),
                    target.format.clone(),
                ],
            );
        }
    }
    Ok(cert.render_targets.len())
}

fn check_render_pipelines(cert: &Certificate) -> Result<usize, KernelError> {
    let graphics: IndexSet<&str> = cert
        .graphics
        .iter()
        .map(|graphics| graphics.name.as_str())
        .collect();
    let targets: IndexSet<&str> = cert
        .render_targets
        .iter()
        .map(|target| target.name.as_str())
        .collect();
    let mut names = IndexSet::new();
    for pipeline in &cert.render_pipelines {
        require_evidence("render-pipeline", &pipeline.name, &pipeline.evidence)?;
        if !names.insert(pipeline.name.as_str()) {
            return fail(
                InstabilityKind::RenderPipelineInadmissible,
                "render pipeline names must be unique",
                vec![pipeline.name.clone()],
            );
        }
        if !graphics.contains(pipeline.graphics.as_str()) {
            return fail(
                InstabilityKind::UnknownReference,
                "render pipeline references undeclared graphics contract",
                vec![pipeline.name.clone(), pipeline.graphics.clone()],
            );
        }
        if !targets.contains(pipeline.target.as_str()) {
            return fail(
                InstabilityKind::UnknownReference,
                "render pipeline references undeclared render target",
                vec![pipeline.name.clone(), pipeline.target.clone()],
            );
        }
        if pipeline.entry.is_empty()
            || !matches!(pipeline.mode.as_str(), "interpret" | "ir" | "native")
        {
            return fail(
                InstabilityKind::RenderPipelineInadmissible,
                "render pipeline must name an entry point and registered execution mode",
                vec![pipeline.name.clone(), pipeline.mode.clone()],
            );
        }
    }
    Ok(cert.render_pipelines.len())
}

fn check_benchmarks(cert: &Certificate) -> Result<usize, KernelError> {
    let graphics: IndexSet<&str> = cert
        .graphics
        .iter()
        .map(|graphics| graphics.name.as_str())
        .collect();
    let mut names = IndexSet::new();
    for benchmark in &cert.benchmarks {
        require_evidence("benchmark", &benchmark.name, &benchmark.evidence)?;
        if !names.insert(benchmark.name.as_str()) {
            return fail(
                InstabilityKind::BenchmarkInadmissible,
                "benchmark names must be unique",
                vec![benchmark.name.clone()],
            );
        }
        if !graphics.contains(benchmark.graphics.as_str()) {
            return fail(
                InstabilityKind::UnknownReference,
                "benchmark references undeclared graphics contract",
                vec![benchmark.name.clone(), benchmark.graphics.clone()],
            );
        }
        if benchmark.entry.is_empty() || benchmark.iterations == 0 || benchmark.iterations > 10_000
        {
            return fail(
                InstabilityKind::BenchmarkInadmissible,
                "benchmark must name an entry point and bounded positive iteration count",
                vec![benchmark.name.clone(), benchmark.iterations.to_string()],
            );
        }
    }
    Ok(cert.benchmarks.len())
}

fn check_tensors(cert: &Certificate) -> Result<usize, KernelError> {
    let mut names = IndexSet::new();
    for tensor in &cert.tensors {
        require_evidence("tensor", &tensor.name, &tensor.evidence)?;
        if !names.insert(tensor.name.as_str()) {
            return fail(
                InstabilityKind::TensorInadmissible,
                "tensor names must be unique",
                vec![tensor.name.clone()],
            );
        }
        if tensor.name.is_empty()
            || tensor.shape.is_empty()
            || !registered_tensor_dtype(&tensor.dtype)
            || !matches!(tensor.gradient.as_str(), "none" | "tracked")
            || tensor.layout.is_empty()
            || tensor.shape.iter().any(|dim| !valid_shape_dim(dim))
        {
            return fail(
                InstabilityKind::TensorInadmissible,
                "tensor row must declare shape, dtype, gradient policy, and layout",
                vec![
                    tensor.name.clone(),
                    tensor.shape.join(","),
                    tensor.dtype.clone(),
                    tensor.gradient.clone(),
                    tensor.layout.clone(),
                ],
            );
        }
    }
    Ok(cert.tensors.len())
}

fn check_accelerators(cert: &Certificate) -> Result<usize, KernelError> {
    let mut names = IndexSet::new();
    for accelerator in &cert.accelerators {
        require_evidence("accelerator", &accelerator.name, &accelerator.evidence)?;
        if !names.insert(accelerator.name.as_str()) {
            return fail(
                InstabilityKind::AcceleratorInadmissible,
                "accelerator names must be unique",
                vec![accelerator.name.clone()],
            );
        }
        if accelerator.name.is_empty()
            || accelerator.kind.is_empty()
            || accelerator.memory.is_empty()
            || !registered_tensor_dtype(&accelerator.precision)
            || accelerator.supports.is_empty()
            || accelerator.supports.iter().any(|op| !valid_symbol(op))
        {
            return fail(
                InstabilityKind::AcceleratorInadmissible,
                "accelerator row must declare kind, memory, precision, and supported ops",
                vec![
                    accelerator.name.clone(),
                    accelerator.kind.clone(),
                    accelerator.memory.clone(),
                    accelerator.precision.clone(),
                ],
            );
        }
    }
    Ok(cert.accelerators.len())
}

fn check_datasets(cert: &Certificate) -> Result<usize, KernelError> {
    let tensors: IndexSet<&str> = cert
        .tensors
        .iter()
        .map(|tensor| tensor.name.as_str())
        .collect();
    let mut names = IndexSet::new();
    for dataset in &cert.datasets {
        require_evidence("dataset", &dataset.name, &dataset.evidence)?;
        if !names.insert(dataset.name.as_str()) {
            return fail(
                InstabilityKind::DatasetInadmissible,
                "dataset names must be unique",
                vec![dataset.name.clone()],
            );
        }
        if dataset.name.is_empty()
            || dataset.tensors.is_empty()
            || dataset.source.is_empty()
            || !dataset.source_digest.starts_with("sha256:")
        {
            return fail(
                InstabilityKind::DatasetInadmissible,
                "dataset row must name tensors, source, and sha256 digest",
                vec![dataset.name.clone(), dataset.source_digest.clone()],
            );
        }
        for tensor in &dataset.tensors {
            if !tensors.contains(tensor.as_str()) {
                return fail(
                    InstabilityKind::UnknownReference,
                    "dataset references undeclared tensor",
                    vec![dataset.name.clone(), tensor.clone()],
                );
            }
        }
    }
    Ok(cert.datasets.len())
}

fn check_models(cert: &Certificate) -> Result<usize, KernelError> {
    let tensors: IndexSet<&str> = cert
        .tensors
        .iter()
        .map(|tensor| tensor.name.as_str())
        .collect();
    let mut names = IndexSet::new();
    for model in &cert.models {
        require_evidence("model", &model.name, &model.evidence)?;
        if !names.insert(model.name.as_str()) {
            return fail(
                InstabilityKind::ModelInadmissible,
                "model names must be unique",
                vec![model.name.clone()],
            );
        }
        if model.name.is_empty()
            || model.entry.is_empty()
            || model.inputs.is_empty()
            || model.outputs.is_empty()
            || model.ops.is_empty()
            || model.loss.is_empty()
        {
            return fail(
                InstabilityKind::ModelInadmissible,
                "model row must declare entry, inputs, outputs, ops, and loss",
                vec![model.name.clone()],
            );
        }
        for tensor in model
            .inputs
            .iter()
            .chain(model.parameters.iter())
            .chain(model.outputs.iter())
        {
            if !tensors.contains(tensor.as_str()) {
                return fail(
                    InstabilityKind::UnknownReference,
                    "model references undeclared tensor",
                    vec![model.name.clone(), tensor.clone()],
                );
            }
        }
        let mut available_values: IndexSet<String> = model
            .inputs
            .iter()
            .chain(model.parameters.iter())
            .cloned()
            .collect();
        for op in &model.ops {
            let parsed = check_model_op_shape(model, op)?;
            for arg in &parsed.args {
                if !available_values.contains(arg) {
                    return fail(
                        InstabilityKind::ModelInadmissible,
                        "model op references a value that is not yet available",
                        vec![model.name.clone(), op.clone(), arg.clone()],
                    );
                }
            }
            available_values.insert(parsed.output);
        }
        for output in &model.outputs {
            if !available_values.contains(output) {
                return fail(
                    InstabilityKind::ModelInadmissible,
                    "model output is not produced by inputs, parameters, or ops",
                    vec![model.name.clone(), output.clone()],
                );
            }
        }
        if !available_values.contains(&model.loss) {
            return fail(
                InstabilityKind::ModelInadmissible,
                "model loss is not produced by inputs, parameters, or ops",
                vec![model.name.clone(), model.loss.clone()],
            );
        }
    }
    Ok(cert.models.len())
}

fn check_trainings(cert: &Certificate) -> Result<usize, KernelError> {
    let models: IndexMap<&str, &ent_core::ModelContract> = cert
        .models
        .iter()
        .map(|model| (model.name.as_str(), model))
        .collect();
    let datasets: IndexSet<&str> = cert
        .datasets
        .iter()
        .map(|dataset| dataset.name.as_str())
        .collect();
    let artifacts: IndexSet<&str> = cert
        .artifacts
        .iter()
        .map(|artifact| artifact.name.as_str())
        .collect();
    let accelerators: IndexMap<&str, &ent_core::AcceleratorContract> = cert
        .accelerators
        .iter()
        .map(|accelerator| (accelerator.name.as_str(), accelerator))
        .collect();
    let mut names = IndexSet::new();
    for training in &cert.trainings {
        require_evidence("training", &training.name, &training.evidence)?;
        if !names.insert(training.name.as_str()) {
            return fail(
                InstabilityKind::TrainingInadmissible,
                "training names must be unique",
                vec![training.name.clone()],
            );
        }
        let Some(model) = models.get(training.model.as_str()) else {
            return fail(
                InstabilityKind::UnknownReference,
                "training references undeclared model",
                vec![training.name.clone(), training.model.clone()],
            );
        };
        if !datasets.contains(training.dataset.as_str()) {
            return fail(
                InstabilityKind::UnknownReference,
                "training references undeclared dataset",
                vec![training.name.clone(), training.dataset.clone()],
            );
        }
        if let Some(artifact) = &training.artifact {
            if !artifacts.contains(artifact.as_str()) {
                return fail(
                    InstabilityKind::UnknownReference,
                    "training references undeclared artifact",
                    vec![training.name.clone(), artifact.clone()],
                );
            }
        }
        let Some(accelerator) = accelerators.get(training.accelerator.as_str()) else {
            return fail(
                InstabilityKind::UnknownReference,
                "training references undeclared accelerator",
                vec![training.name.clone(), training.accelerator.clone()],
            );
        };
        for op in &model.ops {
            let op_name = model_op_name(op)?;
            if !accelerator.supports.contains(&op_name) {
                return fail(
                    InstabilityKind::TrainingInadmissible,
                    "training accelerator does not cover a model op",
                    vec![training.name.clone(), training.accelerator.clone(), op_name],
                );
            }
        }
        if training.optimizer.is_empty()
            || training.objective.is_empty()
            || training.accelerator.is_empty()
            || training
                .artifact
                .as_deref()
                .is_some_and(|artifact| !valid_symbol(artifact))
            || training.steps == 0
            || training.batch == 0
            || !training.learning_rate.is_finite()
            || training.learning_rate <= 0.0
        {
            return fail(
                InstabilityKind::TrainingInadmissible,
                "training row must declare optimizer, objective, positive steps, batch, and learning rate",
                vec![
                    training.name.clone(),
                    training.optimizer.clone(),
                    training.learning_rate.to_string(),
                ],
            );
        }
    }
    Ok(cert.trainings.len())
}

fn model_op_name(op: &str) -> Result<String, KernelError> {
    let Some((call, _)) = op.split_once("->") else {
        return fail(
            InstabilityKind::ModelInadmissible,
            "model op must be written as op(args)->value",
            vec![op.to_owned()],
        );
    };
    let Some((name, _)) = call.split_once('(') else {
        return fail(
            InstabilityKind::ModelInadmissible,
            "model op lacks argument list",
            vec![op.to_owned()],
        );
    };
    Ok(name.trim().to_owned())
}

fn registered_tensor_dtype(dtype: &str) -> bool {
    matches!(
        dtype,
        "f16" | "bf16" | "f32" | "f64" | "i32" | "i64" | "bool"
    )
}

fn valid_shape_dim(dim: &str) -> bool {
    dim.parse::<u64>().is_ok_and(|value| value > 0) || valid_symbol(dim)
}

fn valid_symbol(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(ch) if ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch == '-' || ch.is_ascii_alphanumeric())
}

fn valid_module_path(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('.')
            .all(|segment| !segment.is_empty() && valid_symbol(segment))
}

fn valid_framework_target(value: &str) -> bool {
    valid_module_path(value) || value.split("::").all(valid_module_path)
}

fn valid_sha256_uri(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn portable_relative_path(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value.contains('\0')
        || value.contains(':')
    {
        return false;
    }
    let mut has_segment = false;
    for segment in value.split('/') {
        if segment.is_empty() {
            return false;
        }
        if segment == "." {
            continue;
        }
        if segment == ".." {
            return false;
        }
        has_segment = true;
    }
    has_segment
}

fn parse_lowering_mappings(
    lowering: &ent_core::LoweringContract,
) -> Result<IndexSet<&str>, KernelError> {
    let mut mapped_ops = IndexSet::new();
    for mapping in &lowering.mappings {
        let Some((op, targets)) = mapping.split_once('=') else {
            return fail(
                InstabilityKind::LoweringInadmissible,
                "lowering mapping must use op=target(+target) form",
                vec![lowering.name.clone(), mapping.clone()],
            );
        };
        let op = op.trim();
        if !valid_symbol(op) || !mapped_ops.insert(op) {
            return fail(
                InstabilityKind::LoweringInadmissible,
                "lowering mapping must name each source op once",
                vec![lowering.name.clone(), mapping.clone()],
            );
        }
        let targets = targets
            .split('+')
            .map(str::trim)
            .filter(|target| !target.is_empty())
            .collect::<Vec<_>>();
        if targets.is_empty() || targets.iter().any(|target| !valid_framework_target(target)) {
            return fail(
                InstabilityKind::LoweringInadmissible,
                "lowering mapping target must be an explicit framework primitive path",
                vec![lowering.name.clone(), mapping.clone()],
            );
        }
    }
    Ok(mapped_ops)
}

fn valid_metric_requirement(requirement: &str) -> bool {
    parse_metric_requirement(requirement).is_some()
}

fn parse_metric_requirement(requirement: &str) -> Option<(&str, &str, f64)> {
    for op in ["<=", ">=", "==", "<", ">"] {
        if let Some((metric, value)) = requirement.split_once(op) {
            let metric = metric.trim();
            let value = value.trim().parse::<f64>().ok()?;
            if valid_metric_path(metric) && value.is_finite() {
                return Some((metric, op, value));
            }
        }
    }
    None
}

fn valid_metric_path(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('.')
            .all(|segment| !segment.is_empty() && valid_symbol(segment))
}

struct ModelOpParts {
    args: Vec<String>,
    output: String,
}

fn check_model_op_shape(
    model: &ent_core::ModelContract,
    op: &str,
) -> Result<ModelOpParts, KernelError> {
    let Some((call, output)) = op.split_once("->") else {
        return fail(
            InstabilityKind::ModelInadmissible,
            "model op must be written as op(args)->value",
            vec![model.name.clone(), op.to_owned()],
        );
    };
    let Some(open) = call.find('(') else {
        return fail(
            InstabilityKind::ModelInadmissible,
            "model op lacks argument list",
            vec![model.name.clone(), op.to_owned()],
        );
    };
    let Some(args) = call.strip_suffix(')') else {
        return fail(
            InstabilityKind::ModelInadmissible,
            "model op argument list is not closed",
            vec![model.name.clone(), op.to_owned()],
        );
    };
    let op_name = call[..open].trim();
    let args = &args[open + 1..];
    let output = output.trim();
    if !valid_symbol(op_name) || !valid_symbol(output) {
        return fail(
            InstabilityKind::ModelInadmissible,
            "model op must name a symbolic op and output",
            vec![model.name.clone(), op.to_owned()],
        );
    }
    let args = args
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if args.iter().any(|arg| arg.is_empty() || !valid_symbol(arg)) {
        return fail(
            InstabilityKind::ModelInadmissible,
            "model op arguments must be symbolic tensor names",
            vec![model.name.clone(), op.to_owned()],
        );
    }
    Ok(ModelOpParts {
        args,
        output: output.to_owned(),
    })
}

fn check_proof_artifacts(cert: &Certificate) -> Result<usize, KernelError> {
    let mut names = IndexSet::new();
    for artifact in &cert.proof_artifacts {
        require_evidence("proof-artifact", &artifact.name, &artifact.evidence)?;
        if !names.insert(artifact.name.as_str()) {
            return fail(
                InstabilityKind::ProofArtifactInadmissible,
                "proof artifact names must be unique",
                vec![artifact.name.clone()],
            );
        }
        if artifact.name.is_empty()
            || artifact.module.is_empty()
            || artifact.digest.is_empty()
            || artifact.obligations.is_empty()
        {
            return fail(
                InstabilityKind::ProofArtifactInadmissible,
                "proof artifact must name module, digest, and obligations",
                vec![artifact.name.clone()],
            );
        }
        if artifact.module.contains("..") || artifact.module.starts_with('/') {
            return fail(
                InstabilityKind::ProofArtifactInadmissible,
                "proof artifact module path must be repo-relative and normalized",
                vec![artifact.name.clone(), artifact.module.clone()],
            );
        }
        if !artifact.digest.starts_with("sha256:") {
            return fail(
                InstabilityKind::ProofArtifactInadmissible,
                "proof artifact digest must use an explicit sha256 URI",
                vec![artifact.name.clone(), artifact.digest.clone()],
            );
        }
    }
    Ok(cert.proof_artifacts.len())
}

fn check_machines(cert: &Certificate) -> Result<usize, KernelError> {
    let mut names = IndexSet::new();
    for machine in &cert.machines {
        require_evidence("machine", &machine.id, &machine.evidence)?;
        if !names.insert(machine.id.as_str()) {
            return fail(
                InstabilityKind::MachineInadmissible,
                "machine ids must be unique",
                vec![machine.id.clone()],
            );
        }
        if machine.id.is_empty()
            || machine.isa.is_empty()
            || machine.profile.is_empty()
            || machine.semantic_source.is_empty()
            || machine.source_digest.is_empty()
        {
            return fail(
                InstabilityKind::MachineInadmissible,
                "machine row must name ISA, profile, semantic source, and source digest",
                vec![machine.id.clone()],
            );
        }
        if machine.word_bits == 0 || machine.word_bits % 8 != 0 {
            return fail(
                InstabilityKind::MachineInadmissible,
                "machine word width must be a positive byte multiple",
                vec![machine.id.clone(), machine.word_bits.to_string()],
            );
        }
        if !machine.source_digest.starts_with("sha256:") {
            return fail(
                InstabilityKind::MachineInadmissible,
                "machine semantic source digest must use an explicit sha256 URI",
                vec![machine.id.clone(), machine.source_digest.clone()],
            );
        }
    }
    Ok(cert.machines.len())
}

fn check_machine_memory(cert: &Certificate) -> Result<usize, KernelError> {
    let machines: IndexSet<&str> = cert
        .machines
        .iter()
        .map(|machine| machine.id.as_str())
        .collect();
    let mut names = IndexSet::new();
    for memory in &cert.memory {
        require_evidence("memory", &memory.name, &memory.evidence)?;
        if !names.insert(memory.name.as_str()) {
            return fail(
                InstabilityKind::MemoryInadmissible,
                "memory contract names must be unique",
                vec![memory.name.clone()],
            );
        }
        if !machines.contains(memory.machine.as_str()) {
            return fail(
                InstabilityKind::UnknownReference,
                "memory contract references undeclared machine",
                vec![memory.name.clone(), memory.machine.clone()],
            );
        }
        if memory.address_bits == 0
            || memory.regions.is_empty()
            || memory.frame_conditions.is_empty()
        {
            return fail(
                InstabilityKind::MemoryInadmissible,
                "memory contract must declare address width, regions, and frame conditions",
                vec![memory.name.clone()],
            );
        }
        let mut regions: Vec<(String, u64, u64)> = Vec::new();
        for region in &memory.regions {
            if region.name.is_empty() || region.size == 0 || region.permissions.is_empty() {
                return fail(
                    InstabilityKind::MemoryInadmissible,
                    "memory region must name non-empty address range and permissions",
                    vec![memory.name.clone(), region.name.clone()],
                );
            }
            let end =
                region
                    .base
                    .checked_add(region.size)
                    .ok_or_else(|| KernelError::Instability {
                        kind: InstabilityKind::MemoryInadmissible,
                        message: "memory region address range overflows".to_owned(),
                        evidence: vec![memory.name.clone(), region.name.clone()],
                    })?;
            for (existing_name, existing_start, existing_end) in &regions {
                if region.base < *existing_end && end > *existing_start {
                    return fail(
                        InstabilityKind::MemoryInadmissible,
                        "memory regions must not overlap",
                        vec![
                            memory.name.clone(),
                            region.name.clone(),
                            existing_name.clone(),
                        ],
                    );
                }
            }
            regions.push((region.name.clone(), region.base, end));
        }
    }
    Ok(cert.memory.len())
}

fn check_instructions(cert: &Certificate) -> Result<usize, KernelError> {
    let machines: IndexSet<&str> = cert
        .machines
        .iter()
        .map(|machine| machine.id.as_str())
        .collect();
    let artifacts: IndexSet<&str> = cert
        .proof_artifacts
        .iter()
        .map(|artifact| artifact.name.as_str())
        .collect();
    let mut names = IndexSet::new();
    for instruction in &cert.instructions {
        require_evidence("instruction", &instruction.name, &instruction.evidence)?;
        if !names.insert(instruction.name.as_str()) {
            return fail(
                InstabilityKind::InstructionInadmissible,
                "instruction names must be unique",
                vec![instruction.name.clone()],
            );
        }
        if !machines.contains(instruction.machine.as_str()) {
            return fail(
                InstabilityKind::UnknownReference,
                "instruction references undeclared machine",
                vec![instruction.name.clone(), instruction.machine.clone()],
            );
        }
        if !artifacts.contains(instruction.proof_artifact.as_str()) {
            return fail(
                InstabilityKind::UnknownReference,
                "instruction references undeclared proof artifact",
                vec![instruction.name.clone(), instruction.proof_artifact.clone()],
            );
        }
        if instruction.mnemonic.is_empty()
            || instruction.encoding.is_empty()
            || instruction.semantics.is_empty()
            || instruction.effects.is_empty()
        {
            return fail(
                InstabilityKind::InstructionInadmissible,
                "instruction row must declare mnemonic, encoding, semantics, and effects",
                vec![instruction.name.clone()],
            );
        }
    }
    Ok(cert.instructions.len())
}

fn check_canonicals(cert: &Certificate) -> Result<usize, KernelError> {
    let mut names = IndexSet::new();
    for canonical in &cert.canonicals {
        require_evidence("canonical", &canonical.name, &canonical.evidence)?;
        if !names.insert(canonical.name.as_str()) {
            return fail(
                InstabilityKind::CanonicalInadmissible,
                "canonical contracts must have unique names",
                vec![canonical.name.clone()],
            );
        }
        if !valid_symbol(&canonical.name)
            || !valid_symbol(&canonical.format)
            || canonical.fields.is_empty()
            || canonical.fields.iter().any(|field| !valid_symbol(field))
        {
            return fail(
                InstabilityKind::CanonicalInadmissible,
                "canonical row must name a format and symbolic serialization fields",
                vec![
                    canonical.name.clone(),
                    canonical.format.clone(),
                    canonical.fields.join(","),
                ],
            );
        }
    }
    Ok(cert.canonicals.len())
}

fn check_artifacts(cert: &Certificate) -> Result<usize, KernelError> {
    let canonicals: IndexSet<&str> = cert
        .canonicals
        .iter()
        .map(|canonical| canonical.name.as_str())
        .collect();
    let tensors: IndexSet<&str> = cert
        .tensors
        .iter()
        .map(|tensor| tensor.name.as_str())
        .collect();
    let mut names = IndexSet::new();
    for artifact in &cert.artifacts {
        require_evidence("artifact", &artifact.name, &artifact.evidence)?;
        if !names.insert(artifact.name.as_str()) {
            return fail(
                InstabilityKind::ArtifactInadmissible,
                "artifact contracts must have unique names",
                vec![artifact.name.clone()],
            );
        }
        if !valid_symbol(&artifact.name)
            || !valid_symbol(&artifact.kind)
            || artifact.tensors.is_empty()
            || !valid_sha256_uri(&artifact.digest)
            || !portable_relative_path(&artifact.manifest)
        {
            return fail(
                InstabilityKind::ArtifactInadmissible,
                "artifact row must bind tensors to a portable manifest path and sha256 digest",
                vec![
                    artifact.name.clone(),
                    artifact.manifest.clone(),
                    artifact.digest.clone(),
                ],
            );
        }
        if !canonicals.contains(artifact.canonical.as_str()) {
            return fail(
                InstabilityKind::UnknownReference,
                "artifact references undeclared canonical contract",
                vec![artifact.name.clone(), artifact.canonical.clone()],
            );
        }
        let mut seen_tensors = IndexSet::new();
        for tensor in &artifact.tensors {
            if !seen_tensors.insert(tensor.as_str()) {
                return fail(
                    InstabilityKind::ArtifactInadmissible,
                    "artifact tensor list must not contain duplicates",
                    vec![artifact.name.clone(), tensor.clone()],
                );
            }
            if !tensors.contains(tensor.as_str()) {
                return fail(
                    InstabilityKind::UnknownReference,
                    "artifact references undeclared tensor",
                    vec![artifact.name.clone(), tensor.clone()],
                );
            }
        }
    }
    Ok(cert.artifacts.len())
}

fn check_lowerings(cert: &Certificate) -> Result<usize, KernelError> {
    let models: IndexMap<&str, &ent_core::ModelContract> = cert
        .models
        .iter()
        .map(|model| (model.name.as_str(), model))
        .collect();
    let mut names = IndexSet::new();
    for lowering in &cert.lowerings {
        require_evidence("lowering", &lowering.name, &lowering.evidence)?;
        if !names.insert(lowering.name.as_str()) {
            return fail(
                InstabilityKind::LoweringInadmissible,
                "lowering contracts must have unique names",
                vec![lowering.name.clone()],
            );
        }
        let Some(model) = models.get(lowering.model.as_str()) else {
            return fail(
                InstabilityKind::UnknownReference,
                "lowering references undeclared model",
                vec![lowering.name.clone(), lowering.model.clone()],
            );
        };
        if !valid_symbol(&lowering.name)
            || !valid_symbol(&lowering.framework)
            || lowering.mappings.is_empty()
            || !lowering.tolerance.is_finite()
            || lowering.tolerance < 0.0
        {
            return fail(
                InstabilityKind::LoweringInadmissible,
                "lowering row must name framework mappings and non-negative tolerance",
                vec![
                    lowering.name.clone(),
                    lowering.framework.clone(),
                    lowering.tolerance.to_string(),
                ],
            );
        }
        let mapped_ops = parse_lowering_mappings(lowering)?;
        for op in &model.ops {
            let op_name = model_op_name(op)?;
            if !mapped_ops.contains(op_name.as_str()) {
                return fail(
                    InstabilityKind::LoweringInadmissible,
                    "lowering must cover every model op explicitly",
                    vec![lowering.name.clone(), model.name.clone(), op_name],
                );
            }
        }
    }
    Ok(cert.lowerings.len())
}

fn check_executors(cert: &Certificate) -> Result<usize, KernelError> {
    let artifacts: IndexSet<&str> = cert
        .artifacts
        .iter()
        .map(|artifact| artifact.name.as_str())
        .collect();
    let mut names = IndexSet::new();
    for executor in &cert.executors {
        require_evidence("executor", &executor.name, &executor.evidence)?;
        if !names.insert(executor.name.as_str()) {
            return fail(
                InstabilityKind::ExecutorInadmissible,
                "executor contracts must have unique names",
                vec![executor.name.clone()],
            );
        }
        if !valid_symbol(&executor.name)
            || !valid_symbol(&executor.framework)
            || !valid_module_path(&executor.module)
            || !valid_symbol(&executor.function)
            || !valid_symbol(&executor.device)
            || !valid_symbol(&executor.network)
            || executor.write_paths.is_empty()
            || executor
                .write_paths
                .iter()
                .any(|path| !portable_relative_path(path))
        {
            return fail(
                InstabilityKind::ExecutorInadmissible,
                "executor row must declare explicit module/function/device/network and scoped writes",
                vec![executor.name.clone(), executor.module.clone()],
            );
        }
        for artifact in &executor.read_artifacts {
            if !artifacts.contains(artifact.as_str()) {
                return fail(
                    InstabilityKind::UnknownReference,
                    "executor references undeclared readable artifact",
                    vec![executor.name.clone(), artifact.clone()],
                );
            }
        }
    }
    Ok(cert.executors.len())
}

fn check_witnesses(cert: &Certificate) -> Result<usize, KernelError> {
    let trainings: IndexMap<&str, &ent_core::TrainingContract> = cert
        .trainings
        .iter()
        .map(|training| (training.name.as_str(), training))
        .collect();
    let models: IndexMap<&str, &ent_core::ModelContract> = cert
        .models
        .iter()
        .map(|model| (model.name.as_str(), model))
        .collect();
    let artifacts: IndexMap<&str, &ent_core::ArtifactContract> = cert
        .artifacts
        .iter()
        .map(|artifact| (artifact.name.as_str(), artifact))
        .collect();
    let lowerings: IndexMap<&str, &ent_core::LoweringContract> = cert
        .lowerings
        .iter()
        .map(|lowering| (lowering.name.as_str(), lowering))
        .collect();
    let executors: IndexMap<&str, &ent_core::ExecutorContract> = cert
        .executors
        .iter()
        .map(|executor| (executor.name.as_str(), executor))
        .collect();
    let mut names = IndexSet::new();
    for witness in &cert.witnesses {
        require_evidence("witness", &witness.name, &witness.evidence)?;
        if !names.insert(witness.name.as_str()) {
            return fail(
                InstabilityKind::WitnessInadmissible,
                "witness contracts must have unique names",
                vec![witness.name.clone()],
            );
        }
        let Some(training) = trainings.get(witness.training.as_str()) else {
            return fail(
                InstabilityKind::UnknownReference,
                "witness references undeclared training",
                vec![witness.name.clone(), witness.training.clone()],
            );
        };
        let Some(model) = models.get(training.model.as_str()) else {
            return fail(
                InstabilityKind::UnknownReference,
                "witness training references undeclared model",
                vec![witness.name.clone(), training.model.clone()],
            );
        };
        let Some(artifact) = artifacts.get(witness.artifact.as_str()) else {
            return fail(
                InstabilityKind::UnknownReference,
                "witness references undeclared artifact",
                vec![witness.name.clone(), witness.artifact.clone()],
            );
        };
        let Some(lowering) = lowerings.get(witness.lowering.as_str()) else {
            return fail(
                InstabilityKind::UnknownReference,
                "witness references undeclared lowering",
                vec![witness.name.clone(), witness.lowering.clone()],
            );
        };
        let Some(executor) = executors.get(witness.executor.as_str()) else {
            return fail(
                InstabilityKind::UnknownReference,
                "witness references undeclared executor",
                vec![witness.name.clone(), witness.executor.clone()],
            );
        };
        if !valid_symbol(&witness.name)
            || !portable_relative_path(&witness.manifest)
            || witness.requirements.is_empty()
            || witness
                .requirements
                .iter()
                .any(|requirement| !valid_metric_requirement(requirement))
        {
            return fail(
                InstabilityKind::WitnessInadmissible,
                "witness row must declare manifest and parseable metric requirements",
                vec![witness.name.clone(), witness.manifest.clone()],
            );
        }
        if training.artifact.as_deref() != Some(artifact.name.as_str()) {
            return fail(
                InstabilityKind::WitnessInadmissible,
                "witness artifact must be explicitly selected by its training row",
                vec![
                    witness.name.clone(),
                    training.artifact.clone().unwrap_or_default(),
                    artifact.name.clone(),
                ],
            );
        }
        if lowering.model != training.model {
            return fail(
                InstabilityKind::WitnessInadmissible,
                "witness lowering must target the training model",
                vec![
                    witness.name.clone(),
                    lowering.model.clone(),
                    training.model.clone(),
                ],
            );
        }
        if !executor.read_artifacts.contains(&artifact.name) {
            return fail(
                InstabilityKind::WitnessInadmissible,
                "witness executor must read the bound artifact",
                vec![
                    witness.name.clone(),
                    executor.name.clone(),
                    artifact.name.clone(),
                ],
            );
        }
        for input in &model.inputs {
            if !artifact.tensors.contains(input) {
                return fail(
                    InstabilityKind::WitnessInadmissible,
                    "witness artifact must bind every model input tensor",
                    vec![witness.name.clone(), artifact.name.clone(), input.clone()],
                );
            }
        }
    }
    Ok(cert.witnesses.len())
}

fn check_abis(cert: &Certificate) -> Result<usize, KernelError> {
    let machines: IndexSet<&str> = cert
        .machines
        .iter()
        .map(|machine| machine.id.as_str())
        .collect();
    let mut names = IndexSet::new();
    for abi in &cert.abis {
        require_evidence("abi", &abi.name, &abi.evidence)?;
        if !names.insert(abi.name.as_str()) {
            return fail(
                InstabilityKind::AbiInadmissible,
                "ABI contract names must be unique",
                vec![abi.name.clone()],
            );
        }
        if !machines.contains(abi.machine.as_str()) {
            return fail(
                InstabilityKind::UnknownReference,
                "ABI contract references undeclared machine",
                vec![abi.name.clone(), abi.machine.clone()],
            );
        }
        if abi.target_triple.is_empty()
            || abi.object_format.is_empty()
            || abi.calling_convention.is_empty()
            || abi.external_policy.is_empty()
        {
            return fail(
                InstabilityKind::AbiInadmissible,
                "ABI contract must declare target, object format, calling convention, and external policy",
                vec![abi.name.clone()],
            );
        }
    }
    Ok(cert.abis.len())
}

fn check_proofs(cert: &Certificate) -> Result<usize, KernelError> {
    let mut names = IndexSet::new();
    let environment = CertificateProofEnvironment { cert };
    for proof in &cert.proofs {
        if !names.insert(proof.name.as_str()) {
            return fail(
                InstabilityKind::ProofGap,
                "proof names must be unique",
                vec![proof.name.clone()],
            );
        }

        check_proof(&proof.name, &proof.proposition, &proof.script, &environment)
            .map_err(|error| proof_gap(&proof.name, error))?;
    }
    Ok(cert.proofs.len())
}

fn check_workspace_proof_obligations(cert: &Certificate) -> Result<(), KernelError> {
    for parser in &cert.parsers {
        require_proof(
            cert,
            PropositionKind::ParserAdmissible,
            &parser.name,
            "parser adapter lacks an admissibility proof",
        )?;
    }
    for selection in &cert.selections {
        require_proof(
            cert,
            PropositionKind::SelectionAdmissible,
            &selection.name,
            "selection lacks an admissibility proof",
        )?;
    }
    for transform in &cert.transforms {
        require_proof(
            cert,
            PropositionKind::TransformAdmissible,
            &transform.name,
            "transform lacks an admissibility proof",
        )?;
    }
    for validator in &cert.validators {
        require_proof(
            cert,
            PropositionKind::ValidatorAdmissible,
            &validator.name,
            "validator lacks an admissibility proof",
        )?;
    }
    Ok(())
}

fn check_protocol_proof_obligations(cert: &Certificate) -> Result<(), KernelError> {
    for objective in &cert.objectives {
        require_proof(
            cert,
            PropositionKind::ObjectiveAdmissible,
            &objective.name,
            "objective lacks an admissibility proof",
        )?;
    }
    for milestone in &cert.milestones {
        require_proof(
            cert,
            PropositionKind::MilestoneAdmissible,
            &milestone.name,
            "milestone lacks an admissibility proof",
        )?;
    }
    for task in &cert.tasks {
        require_proof(
            cert,
            PropositionKind::TaskAdmissible,
            &task.name,
            "task lacks an admissibility proof",
        )?;
    }
    for gate in &cert.gates {
        require_proof(
            cert,
            PropositionKind::GateAdmissible,
            &gate.name,
            "gate lacks an admissibility proof",
        )?;
    }
    for decision in &cert.decisions {
        require_proof(
            cert,
            PropositionKind::DecisionAdmissible,
            &decision.name,
            "decision lacks an admissibility proof",
        )?;
    }
    for note in &cert.notes {
        require_proof(
            cert,
            PropositionKind::NoteAdmissible,
            &note.name,
            "note lacks an admissibility proof",
        )?;
    }
    Ok(())
}

fn check_graphics_proof_obligations(cert: &Certificate) -> Result<(), KernelError> {
    for graphics in &cert.graphics {
        require_proof(
            cert,
            PropositionKind::GraphicsAdmissible,
            &graphics.name,
            "graphics contract lacks an admissibility proof",
        )?;
    }
    for target in &cert.render_targets {
        require_proof(
            cert,
            PropositionKind::RenderTargetAdmissible,
            &target.name,
            "render target lacks an admissibility proof",
        )?;
    }
    for pipeline in &cert.render_pipelines {
        require_proof(
            cert,
            PropositionKind::RenderPipelineAdmissible,
            &pipeline.name,
            "render pipeline lacks an admissibility proof",
        )?;
    }
    for benchmark in &cert.benchmarks {
        require_proof(
            cert,
            PropositionKind::BenchmarkAdmissible,
            &benchmark.name,
            "benchmark lacks an admissibility proof",
        )?;
    }
    Ok(())
}

fn check_tensor_proof_obligations(cert: &Certificate) -> Result<(), KernelError> {
    for tensor in &cert.tensors {
        require_proof(
            cert,
            PropositionKind::TensorAdmissible,
            &tensor.name,
            "tensor contract lacks an admissibility proof",
        )?;
    }
    for accelerator in &cert.accelerators {
        require_proof(
            cert,
            PropositionKind::AcceleratorAdmissible,
            &accelerator.name,
            "accelerator contract lacks an admissibility proof",
        )?;
    }
    for dataset in &cert.datasets {
        require_proof(
            cert,
            PropositionKind::DatasetAdmissible,
            &dataset.name,
            "dataset contract lacks an admissibility proof",
        )?;
    }
    for model in &cert.models {
        require_proof(
            cert,
            PropositionKind::ModelAdmissible,
            &model.name,
            "model contract lacks an admissibility proof",
        )?;
    }
    for training in &cert.trainings {
        require_proof(
            cert,
            PropositionKind::TrainingAdmissible,
            &training.name,
            "training contract lacks an admissibility proof",
        )?;
    }
    Ok(())
}

fn check_runtime_boundary_proof_obligations(cert: &Certificate) -> Result<(), KernelError> {
    for canonical in &cert.canonicals {
        require_proof(
            cert,
            PropositionKind::CanonicalAdmissible,
            &canonical.name,
            "canonical contract lacks an admissibility proof",
        )?;
    }
    for artifact in &cert.artifacts {
        require_proof(
            cert,
            PropositionKind::ArtifactBound,
            &artifact.name,
            "artifact lacks a runtime binding proof",
        )?;
    }
    for lowering in &cert.lowerings {
        require_proof(
            cert,
            PropositionKind::LoweringAdmissible,
            &lowering.name,
            "lowering contract lacks an admissibility proof",
        )?;
    }
    for executor in &cert.executors {
        require_proof(
            cert,
            PropositionKind::ExecutorConfined,
            &executor.name,
            "executor contract lacks a confinement proof",
        )?;
    }
    for witness in &cert.witnesses {
        require_proof(
            cert,
            PropositionKind::WitnessSatisfies,
            &witness.name,
            "runtime witness lacks a satisfaction proof",
        )?;
        require_proof(
            cert,
            PropositionKind::TraceEquivalent,
            &witness.name,
            "runtime witness lacks a trace equivalence proof",
        )?;
    }
    Ok(())
}

fn check_machine_proof_obligations(cert: &Certificate) -> Result<(), KernelError> {
    for artifact in &cert.proof_artifacts {
        require_proof(
            cert,
            PropositionKind::ProofArtifactChecked,
            &artifact.name,
            "proof artifact lacks a checked-artifact proof",
        )?;
    }
    for machine in &cert.machines {
        require_proof(
            cert,
            PropositionKind::MachineAdmissible,
            &machine.id,
            "machine contract lacks an admissibility proof",
        )?;
    }
    for memory in &cert.memory {
        require_proof(
            cert,
            PropositionKind::MemoryAdmissible,
            &memory.name,
            "memory contract lacks an admissibility proof",
        )?;
    }
    for instruction in &cert.instructions {
        require_proof(
            cert,
            PropositionKind::InstructionRefines,
            &instruction.name,
            "instruction contract lacks a refinement proof",
        )?;
    }
    for abi in &cert.abis {
        require_proof(
            cert,
            PropositionKind::AbiAdmissible,
            &abi.name,
            "ABI contract lacks an admissibility proof",
        )?;
    }
    Ok(())
}

fn require_proof(
    cert: &Certificate,
    kind: PropositionKind,
    subject: &str,
    message: &str,
) -> Result<(), KernelError> {
    if cert
        .proofs
        .iter()
        .any(|proof| proof.proposition.kind == kind && proof.proposition.subject == subject)
    {
        return Ok(());
    }
    fail(InstabilityKind::ProofGap, message, vec![subject.to_owned()])
}

fn invalid_transform(
    transform: &ent_core::TransformContract,
    message: &str,
) -> Result<(), KernelError> {
    fail(
        InstabilityKind::TransformInadmissible,
        message,
        vec![transform.name.clone(), transform.operation.clone()],
    )
}

fn valid_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
}

fn valid_due(value: &str) -> bool {
    if value == "unscheduled" {
        return true;
    }
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(idx, byte)| matches!(idx, 4 | 7) || byte.is_ascii_digit())
}

fn valid_gate_check(
    check: &str,
    validators: &IndexSet<&str>,
    transforms: &IndexSet<&str>,
) -> Result<bool, KernelError> {
    let Some((kind, subject)) = check.split_once(':') else {
        return Ok(false);
    };
    if subject.trim().is_empty() {
        return Ok(false);
    }
    match kind {
        "validator" => Ok(validators.contains(subject)),
        "transform" => Ok(transforms.contains(subject)),
        "file" => Ok(valid_relative_text(subject)),
        "command" | "record" => Ok(!subject.contains('\0')),
        _ => Ok(false),
    }
}

fn valid_relative_text(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('\0')
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.split('/').any(|part| part.is_empty() || part == "..")
}

struct ProtocolScopes<'a> {
    objectives: IndexSet<&'a str>,
    milestones: IndexSet<&'a str>,
    tasks: IndexSet<&'a str>,
    gates: IndexSet<&'a str>,
    decisions: IndexSet<&'a str>,
    transforms: IndexSet<&'a str>,
    validators: IndexSet<&'a str>,
    selections: IndexSet<&'a str>,
    parsers: IndexSet<&'a str>,
    workspaces: IndexSet<&'a str>,
}

fn protocol_scopes(cert: &Certificate) -> ProtocolScopes<'_> {
    ProtocolScopes {
        objectives: cert
            .objectives
            .iter()
            .map(|objective| objective.name.as_str())
            .collect(),
        milestones: cert
            .milestones
            .iter()
            .map(|milestone| milestone.name.as_str())
            .collect(),
        tasks: cert.tasks.iter().map(|task| task.name.as_str()).collect(),
        gates: cert.gates.iter().map(|gate| gate.name.as_str()).collect(),
        decisions: cert
            .decisions
            .iter()
            .map(|decision| decision.name.as_str())
            .collect(),
        transforms: cert
            .transforms
            .iter()
            .map(|transform| transform.name.as_str())
            .collect(),
        validators: cert
            .validators
            .iter()
            .map(|validator| validator.name.as_str())
            .collect(),
        selections: cert
            .selections
            .iter()
            .map(|selection| selection.name.as_str())
            .collect(),
        parsers: cert
            .parsers
            .iter()
            .map(|parser| parser.name.as_str())
            .collect(),
        workspaces: cert
            .workspaces
            .iter()
            .map(|workspace| workspace.name.as_str())
            .collect(),
    }
}

fn scope_exists(scope: &str, scopes: &ProtocolScopes<'_>) -> bool {
    if let Some((kind, subject)) = scope.split_once(':') {
        return match kind {
            "objective" => scopes.objectives.contains(subject),
            "milestone" => scopes.milestones.contains(subject),
            "task" => scopes.tasks.contains(subject),
            "gate" => scopes.gates.contains(subject),
            "decision" => scopes.decisions.contains(subject),
            "transform" => scopes.transforms.contains(subject),
            "validator" => scopes.validators.contains(subject),
            "selection" => scopes.selections.contains(subject),
            "parser" => scopes.parsers.contains(subject),
            "workspace" => scopes.workspaces.contains(subject),
            _ => false,
        };
    }
    let occurrences = [
        scopes.objectives.contains(scope),
        scopes.milestones.contains(scope),
        scopes.tasks.contains(scope),
        scopes.gates.contains(scope),
        scopes.decisions.contains(scope),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    occurrences == 1
}

fn supported_parser_adapter(language: &str, adapter: &str) -> bool {
    if language.trim().is_empty() {
        return false;
    }
    if matches!(
        (language, adapter),
        ("rust", "tree-sitter")
            | ("c", "tree-sitter")
            | ("cpp", "tree-sitter")
            | ("ent", "native")
            | ("markdown", "pulldown_cmark")
    ) {
        return true;
    }
    if !(language.starts_with("ext:") || language.starts_with("name:")) {
        return false;
    }
    explicit_file_matcher(language) && lexical_comment_adapter(adapter)
}

fn explicit_file_matcher(language: &str) -> bool {
    match language.split_once(':') {
        Some(("ext", body)) => explicit_matcher_body(body.trim_start_matches('.')),
        Some(("name", body)) => explicit_matcher_body(body),
        _ => false,
    }
}

fn explicit_matcher_body(body: &str) -> bool {
    !body.is_empty()
        && !body.contains('/')
        && !body.contains('\\')
        && !body.contains('\0')
        && !body.chars().any(char::is_whitespace)
}

fn lexical_comment_adapter(adapter: &str) -> bool {
    matches!(
        adapter,
        "line-hash"
            | "line-hash-shebang"
            | "line-slash"
            | "line-semicolon"
            | "line-hash-semicolon"
            | "line-double-dash"
            | "batch-comments"
            | "slash-star"
            | "slash-comments"
            | "html-comments"
    )
}

fn parsed_by_predicate(predicate: &str) -> Result<Vec<String>, KernelError> {
    let Some(body) = predicate
        .trim()
        .strip_prefix("parsed_by(")
        .and_then(|tail| tail.strip_suffix(')'))
    else {
        return Ok(vec![]);
    };
    let parsers = body
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if parsers.is_empty() {
        return fail(
            InstabilityKind::SelectionInadmissible,
            "parsed_by predicate must name at least one parser",
            vec![predicate.to_owned()],
        );
    }
    Ok(parsers)
}

struct CertificateProofEnvironment<'a> {
    cert: &'a Certificate,
}

impl ProofEnvironment for CertificateProofEnvironment<'_> {
    fn has_row(&self, kind: &RowKind, subject: &str) -> bool {
        match kind {
            RowKind::Relation => self
                .cert
                .relation_names
                .iter()
                .any(|relation| relation == subject),
            RowKind::Resource => self
                .cert
                .resources
                .iter()
                .any(|resource| resource.name == subject),
            RowKind::Probability => self
                .cert
                .probabilities
                .iter()
                .any(|probability| probability.name == subject),
            RowKind::Invariant => self
                .cert
                .invariants
                .iter()
                .any(|invariant| invariant.name == subject),
            RowKind::Backend => self
                .cert
                .backends
                .iter()
                .any(|backend| backend.node == subject && backend.admissible),
            RowKind::External => self
                .cert
                .external_capabilities
                .iter()
                .any(|external| external.name == subject && external.admissible),
            RowKind::Machine => self
                .cert
                .machines
                .iter()
                .any(|machine| machine.id == subject),
            RowKind::Memory => self.cert.memory.iter().any(|memory| memory.name == subject),
            RowKind::Instruction => self
                .cert
                .instructions
                .iter()
                .any(|instruction| instruction.name == subject),
            RowKind::Abi => self.cert.abis.iter().any(|abi| abi.name == subject),
            RowKind::ProofArtifact => self
                .cert
                .proof_artifacts
                .iter()
                .any(|artifact| artifact.name == subject),
            RowKind::Parser => self
                .cert
                .parsers
                .iter()
                .any(|parser| parser.name == subject),
            RowKind::Selection => self
                .cert
                .selections
                .iter()
                .any(|selection| selection.name == subject),
            RowKind::Transform => self
                .cert
                .transforms
                .iter()
                .any(|transform| transform.name == subject),
            RowKind::Validator => self
                .cert
                .validators
                .iter()
                .any(|validator| validator.name == subject),
            RowKind::Objective => self
                .cert
                .objectives
                .iter()
                .any(|objective| objective.name == subject),
            RowKind::Milestone => self
                .cert
                .milestones
                .iter()
                .any(|milestone| milestone.name == subject),
            RowKind::Task => self.cert.tasks.iter().any(|task| task.name == subject),
            RowKind::Gate => self.cert.gates.iter().any(|gate| gate.name == subject),
            RowKind::Decision => self
                .cert
                .decisions
                .iter()
                .any(|decision| decision.name == subject),
            RowKind::Note => self.cert.notes.iter().any(|note| note.name == subject),
            RowKind::Graphics => self
                .cert
                .graphics
                .iter()
                .any(|graphics| graphics.name == subject),
            RowKind::RenderTarget => self
                .cert
                .render_targets
                .iter()
                .any(|target| target.name == subject),
            RowKind::RenderPipeline => self
                .cert
                .render_pipelines
                .iter()
                .any(|pipeline| pipeline.name == subject),
            RowKind::Benchmark => self
                .cert
                .benchmarks
                .iter()
                .any(|benchmark| benchmark.name == subject),
            RowKind::Tensor => self
                .cert
                .tensors
                .iter()
                .any(|tensor| tensor.name == subject),
            RowKind::Accelerator => self
                .cert
                .accelerators
                .iter()
                .any(|accelerator| accelerator.name == subject),
            RowKind::Dataset => self
                .cert
                .datasets
                .iter()
                .any(|dataset| dataset.name == subject),
            RowKind::Model => self.cert.models.iter().any(|model| model.name == subject),
            RowKind::Training => self
                .cert
                .trainings
                .iter()
                .any(|training| training.name == subject),
            RowKind::Canonical => self
                .cert
                .canonicals
                .iter()
                .any(|canonical| canonical.name == subject),
            RowKind::Artifact => self
                .cert
                .artifacts
                .iter()
                .any(|artifact| artifact.name == subject),
            RowKind::Lowering => self
                .cert
                .lowerings
                .iter()
                .any(|lowering| lowering.name == subject),
            RowKind::Executor => self
                .cert
                .executors
                .iter()
                .any(|executor| executor.name == subject),
            RowKind::Witness => self
                .cert
                .witnesses
                .iter()
                .any(|witness| witness.name == subject),
        }
    }

    fn has_rocq_artifact(&self, module: &str, proposition: &ent_proof::Proposition) -> bool {
        self.cert.proof_artifacts.iter().any(|artifact| {
            artifact.module == module && artifact.obligations.contains(&proposition.subject)
        })
    }

    fn validates_rule(&self, rule: &PrimitiveRule, rows: &[(RowKind, String)]) -> bool {
        match rule {
            PrimitiveRule::WitnessSatisfiesContract => {
                let [(_, witness_name), (_, training_name), (_, artifact_name), (_, executor_name)] =
                    rows
                else {
                    return false;
                };
                let Some(witness) = self
                    .cert
                    .witnesses
                    .iter()
                    .find(|witness| &witness.name == witness_name)
                else {
                    return false;
                };
                let Some(training) = self
                    .cert
                    .trainings
                    .iter()
                    .find(|training| &training.name == training_name)
                else {
                    return false;
                };
                let Some(executor) = self
                    .cert
                    .executors
                    .iter()
                    .find(|executor| &executor.name == executor_name)
                else {
                    return false;
                };
                witness.training == *training_name
                    && witness.artifact == *artifact_name
                    && witness.executor == *executor_name
                    && training.artifact.as_deref() == Some(artifact_name.as_str())
                    && executor.read_artifacts.contains(artifact_name)
            }
            PrimitiveRule::TraceEquivalent => {
                let [(_, witness_name), (_, model_name), (_, lowering_name)] = rows else {
                    return false;
                };
                let Some(witness) = self
                    .cert
                    .witnesses
                    .iter()
                    .find(|witness| &witness.name == witness_name)
                else {
                    return false;
                };
                let Some(lowering) = self
                    .cert
                    .lowerings
                    .iter()
                    .find(|lowering| &lowering.name == lowering_name)
                else {
                    return false;
                };
                let Some(training) = self
                    .cert
                    .trainings
                    .iter()
                    .find(|training| training.name == witness.training)
                else {
                    return false;
                };
                witness.lowering == *lowering_name
                    && lowering.model == *model_name
                    && training.model == *model_name
            }
            _ => true,
        }
    }
}

fn proof_gap(name: &str, error: ProofCheckError) -> KernelError {
    KernelError::Instability {
        kind: InstabilityKind::ProofGap,
        message: error.to_string(),
        evidence: vec![name.to_owned()],
    }
}

fn require_evidence(kind: &str, name: &str, evidence: &str) -> Result<(), KernelError> {
    if evidence.trim().is_empty() {
        return fail(
            InstabilityKind::EvidenceMissing,
            "certificate row lacks explicit evidence",
            vec![kind.to_owned(), name.to_owned()],
        );
    }
    Ok(())
}

fn relation_for<'a>(
    relations: &'a IndexMap<Label, RelationSet>,
    label: &Label,
) -> Result<&'a RelationSet, KernelError> {
    relations
        .get(label)
        .ok_or_else(|| KernelError::Instability {
            kind: InstabilityKind::BadRelation,
            message: "missing relation table".to_owned(),
            evidence: vec![label.display_name()],
        })
}

fn fail<T>(
    kind: InstabilityKind,
    message: impl Into<String>,
    evidence: Vec<String>,
) -> Result<T, KernelError> {
    Err(KernelError::Instability {
        kind,
        message: message.into(),
        evidence,
    })
}

pub fn instability_from_error(error: &KernelError) -> Instability {
    match error {
        KernelError::Instability {
            kind,
            message,
            evidence,
        } => Instability::new(kind.clone(), message.clone(), evidence.clone()),
    }
}
