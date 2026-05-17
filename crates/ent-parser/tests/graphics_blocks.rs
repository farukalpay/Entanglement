use ent_parser::parse_world;
use ent_proof::{PrimitiveRule, ProofStatement, PropositionKind, RowKind};

#[test]
fn parser_accepts_graphics_contract_rows_and_blocks() {
    let source = r#"
world Rendered(agent Viewer) {
  state pixels : Resource
  graphics scene entry main evidence graphics_trace {
    import graphics.raster
    fn main() -> f64 {
      return 1.0
    }
  }
  render-target frame width 320 height 180 format rgba8 evidence target_trace
  render-pipeline pipe graphics scene target frame entry main mode native evidence pipe_trace
  benchmark bench graphics scene entry main warmup 1 iterations 2 evidence bench_trace
  theorem scene_ok : graphics_admissible(scene)
  proof scene_ok {
    let row = row graphics scene
    let fact = rule graphics_admissible_from_graphics(row)
    qed fact
  }
}
"#;
    let ast = parse_world(source).expect("graphics world parses");
    assert_eq!(ast.graphics[0].name, "scene");
    assert_eq!(ast.graphics[0].entry, "main");
    assert_eq!(ast.graphics[0].imports, vec!["graphics.raster"]);
    assert_eq!(ast.render_targets[0].width, 320);
    assert_eq!(ast.render_pipelines[0].mode, "native");
    assert_eq!(ast.benchmarks[0].iterations, 2);
    assert_eq!(
        ast.theorems[0].proposition.kind,
        PropositionKind::GraphicsAdmissible
    );
    assert_eq!(
        ast.proofs[0].script.statements[0],
        ProofStatement::BindRow {
            name: "row".into(),
            kind: RowKind::Graphics,
            subject: "scene".into(),
        }
    );
    assert_eq!(
        ast.proofs[0].script.statements[1],
        ProofStatement::ApplyRule {
            name: "fact".into(),
            rule: PrimitiveRule::GraphicsAdmissibleFromGraphics,
            args: vec!["row".into()],
        }
    );
}

#[test]
fn parser_accepts_tensor_model_and_training_contract_rows() {
    let source = r#"
world TensorProgram(agent Trainer) {
  state values : Resource
  tensor x shape [4,2] dtype f32 gradient none layout row-major evidence x_shape
  tensor y shape [4,2] dtype f32 gradient none layout row-major evidence y_shape
  tensor w shape [2,2] dtype f32 gradient tracked layout row-major evidence w_shape
  tensor logits shape [4,2] dtype f32 gradient none layout row-major evidence logits_shape
  tensor loss shape [1] dtype f32 gradient none layout scalar evidence loss_shape
  accelerator cpu kind cpu memory host precision f32 supports [matmul,softmax_cross_entropy] evidence cpu_trace
  dataset small tensors [x,y,w] source "inline:x=0,0;1,1|y=1,0;0,1|w=0.1,0.2;0.3,0.4" digest "sha256:dataset" evidence data_trace
  model classifier entry forward inputs [x,y] parameters [w] outputs [logits,loss] ops ["matmul(x,w)->logits","softmax_cross_entropy(logits,y)->loss"] loss loss evidence graph_trace
  training train model classifier dataset small accelerator cpu optimizer sgd learning-rate 0.1 steps 2 batch 4 objective minimize_loss evidence train_trace
  theorem x_ok : tensor_admissible(x)
  theorem cpu_ok : accelerator_admissible(cpu)
  theorem data_ok : dataset_admissible(small)
  theorem model_ok : model_admissible(classifier)
  theorem train_ok : training_admissible(train)
  proof x_ok {
    let row = row tensor x
    let fact = rule tensor_admissible_from_tensor(row)
    qed fact
  }
  proof cpu_ok {
    let row = row accelerator cpu
    let fact = rule accelerator_admissible_from_accelerator(row)
    qed fact
  }
  proof data_ok {
    let row = row dataset small
    let fact = rule dataset_admissible_from_dataset(row)
    qed fact
  }
  proof model_ok {
    let row = row model classifier
    let fact = rule model_admissible_from_model(row)
    qed fact
  }
  proof train_ok {
    let row = row training train
    let fact = rule training_admissible_from_training(row)
    qed fact
  }
}
"#;

    let ast = parse_world(source).expect("tensor world parses");
    assert_eq!(ast.tensors.len(), 5);
    assert_eq!(ast.tensors[2].gradient, "tracked");
    assert_eq!(
        ast.accelerators[0].supports,
        vec!["matmul".to_owned(), "softmax_cross_entropy".to_owned()]
    );
    assert_eq!(
        ast.datasets[0].tensors,
        vec!["x".to_owned(), "y".to_owned(), "w".to_owned()]
    );
    assert_eq!(ast.models[0].ops.len(), 2);
    assert_eq!(ast.trainings[0].optimizer, "sgd");
    assert_eq!(
        ast.theorems[0].proposition.kind,
        PropositionKind::TensorAdmissible
    );
    assert_eq!(
        ast.proofs[0].script.statements[0],
        ProofStatement::BindRow {
            name: "row".into(),
            kind: RowKind::Tensor,
            subject: "x".into(),
        }
    );
    assert_eq!(
        ast.proofs[0].script.statements[1],
        ProofStatement::ApplyRule {
            name: "fact".into(),
            rule: PrimitiveRule::TensorAdmissibleFromTensor,
            args: vec!["row".into()],
        }
    );
}
