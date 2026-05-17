From Stdlib Require Import Strings.String Lists.List Arith.PeanoNat.

Import ListNotations.
Open Scope string_scope.

Module RiscVProofs.

Inductive isa := riscv.
Inductive memory_model := rvwmo.
Inductive endian := little.

Record machine_contract := {
  machine_id : string;
  machine_isa : isa;
  machine_profile : string;
  machine_word_bits : nat;
  machine_endian : endian;
  machine_memory : memory_model
}.

Record memory_region := {
  region_name : string;
  region_base : nat;
  region_size : nat
}.

Record memory_contract := {
  memory_name : string;
  memory_machine : string;
  memory_address_bits : nat;
  memory_regions : list memory_region;
  memory_frame : list string
}.

Record instruction_contract := {
  instruction_name : string;
  instruction_machine : string;
  instruction_mnemonic : string;
  instruction_effects : list string
}.

Record abi_contract := {
  abi_name : string;
  abi_machine : string;
  abi_target : string;
  abi_object : string;
  abi_calling : string
}.

Definition rv64 : machine_contract := {|
  machine_id := "rv64";
  machine_isa := riscv;
  machine_profile := "rv64imac";
  machine_word_bits := 64;
  machine_endian := little;
  machine_memory := rvwmo
|}.

Definition host_region : memory_region := {|
  region_name := "ram";
  region_base := 0;
  region_size := 4096
|}.

Definition host_memory : memory_contract := {|
  memory_name := "host";
  memory_machine := "rv64";
  memory_address_bits := 64;
  memory_regions := [host_region];
  memory_frame := ["x-registers"; "pc"]
|}.

Definition add_instruction : instruction_contract := {|
  instruction_name := "add";
  instruction_machine := "rv64";
  instruction_mnemonic := "ADD";
  instruction_effects := ["read:rs1"; "read:rs2"; "write:rd"]
|}.

Definition windows_x64 : abi_contract := {|
  abi_name := "windows_x64";
  abi_machine := "rv64";
  abi_target := "x86_64-pc-windows-msvc";
  abi_object := "pe-coff";
  abi_calling := "win64"
|}.

Definition non_empty_string (value : string) : Prop := value <> EmptyString.

Definition machine_admissible (machine : machine_contract) : Prop :=
  non_empty_string machine.(machine_id) /\
  non_empty_string machine.(machine_profile) /\
  machine.(machine_word_bits) = 64 /\
  machine.(machine_memory) = rvwmo.

Definition memory_admissible (memory : memory_contract) : Prop :=
  memory.(memory_machine) = "rv64" /\
  memory.(memory_address_bits) = 64 /\
  memory.(memory_regions) <> [] /\
  memory.(memory_frame) <> [].

Definition instruction_refines (instruction : instruction_contract) : Prop :=
  instruction.(instruction_machine) = "rv64" /\
  instruction.(instruction_mnemonic) = "ADD" /\
  In "read:rs1" instruction.(instruction_effects) /\
  In "read:rs2" instruction.(instruction_effects) /\
  In "write:rd" instruction.(instruction_effects).

Definition abi_admissible (abi : abi_contract) : Prop :=
  abi.(abi_machine) = "rv64" /\
  non_empty_string abi.(abi_target) /\
  abi.(abi_object) = "pe-coff" /\
  abi.(abi_calling) = "win64".

Theorem rv64_machine_admissible : machine_admissible rv64.
Proof.
  unfold machine_admissible, non_empty_string, rv64; simpl.
  repeat split; discriminate.
Qed.

Theorem host_memory_admissible : memory_admissible host_memory.
Proof.
  unfold memory_admissible, host_memory; simpl.
  repeat split; discriminate.
Qed.

Theorem add_instruction_refines : instruction_refines add_instruction.
Proof.
  unfold instruction_refines, add_instruction; simpl.
  repeat split; auto.
Qed.

Theorem windows_x64_abi_admissible : abi_admissible windows_x64.
Proof.
  unfold abi_admissible, non_empty_string, windows_x64; simpl.
  repeat split; discriminate.
Qed.

End RiscVProofs.
