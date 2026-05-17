use ent_core::{
    Certificate, CheckedRows, Instability, InstabilityKind, KernelFormula, Label, ResourceAccess,
    StateId, TransformTarget, VerificationReport, CERTIFICATE_SCHEMA_VERSION, MAX_MODAL_DIMENSIONS,
    MIN_CERTIFICATE_SCHEMA_VERSION,
};
use ent_proof::{check_proof, ProofCheckError, ProofEnvironment, PropositionKind, RowKind};
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
    checked.proof_artifacts += check_proof_artifacts(cert)?;
    checked.machines += check_machines(cert)?;
    checked.memory += check_machine_memory(cert)?;
    checked.instructions += check_instructions(cert)?;
    checked.abis += check_abis(cert)?;
    checked.proofs += check_proofs(cert)?;
    check_workspace_proof_obligations(cert)?;
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
            if !matches!(transform.target, TransformTarget::File(_))
                || transform.destination.is_some()
                || transform.predicate.is_some()
                || transform.replacement.is_none()
            {
                return invalid_transform(
                    transform,
                    "replacement transforms require a file target plus from/to literals",
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

fn supported_parser_adapter(language: &str, adapter: &str) -> bool {
    matches!(
        (language, adapter),
        ("rust", "tree-sitter")
            | ("c", "tree-sitter")
            | ("cpp", "tree-sitter")
            | ("ent", "native")
            | ("markdown", "pulldown_cmark")
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
        }
    }

    fn has_rocq_artifact(&self, module: &str, proposition: &ent_proof::Proposition) -> bool {
        self.cert.proof_artifacts.iter().any(|artifact| {
            artifact.module == module && artifact.obligations.contains(&proposition.subject)
        })
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
