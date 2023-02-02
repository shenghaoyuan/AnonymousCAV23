From compcert Require Import Integers.
From compcert.arm Require Import AsmSyntax BinSyntax.

From bpf.comm Require Import Flag BinrBPF ListAsArray Regs.
From bpf.model Require Import Encode Syntax.
From bpf.jit.thumb Require Import KeyValue2 LoadStoreRegs JITState.
From bpf.jit.thumb Require Import ThumbEncode ThumbDecode Arm32Reg ThumbJITOpcode ThumbInsOp.

From Coq Require Import List ZArith Arith String.
Import ListNotations.
Open Scope Z_scope.
Open Scope bool_scope.
Open Scope asm.
(** * JIT Compilation *)

(** given a list of bpf instructions, returns a list of thumb instructions *)

Definition jit_pre: list instruction := [Pldr IR12 IR1 (SOimm (Int.repr 8))].

Definition jit_alu32_load_store_aux0 (dst: reg) (src: reg+imm)
  (dst_perm src_perm: LoadStorePerm) (lsr: LoadStoreRegs): option LoadStoreRegs :=
  match src with
  | inl r =>
    match upd_LoadStoreRegs lsr dst LoadAndStore with
    | Some lsr0 => upd_LoadStoreRegs lsr0 r LoadPerm
    | None => None
    end
  | inr i => upd_LoadStoreRegs lsr dst LoadAndStore
  end.

Definition jit_alu32_load_store_aux (ins: bpf_instruction) (lsr: LoadStoreRegs): option LoadStoreRegs :=
  match ins with
  | BPF_BINARY a bop dst src =>
    match a with
    | A32 =>
      match bop with
      | BPF_ADD | BPF_SUB | BPF_MUL | BPF_DIV | BPF_OR | BPF_AND | BPF_XOR
      | BPF_LSH | BPF_RSH | BPF_ARSH =>
        jit_alu32_load_store_aux0 dst src LoadAndStore LoadPerm lsr
      | BPF_MOV =>
        match src with
        | inl r =>
          match upd_LoadStoreRegs lsr dst StorePerm with
          | Some lsr0 => upd_LoadStoreRegs lsr0 r LoadPerm
          | None => None
          end
        | inr i => upd_LoadStoreRegs lsr dst StorePerm
        end
      | BPF_MOD => None
      end
    | A64 => None
    end
  | _ => None
  end.

Fixpoint jit_alu32_load_store (l: list bpf_instruction) (lsr: LoadStoreRegs): option LoadStoreRegs :=
  match l with
  | [] => Some lsr
  | hd :: tl =>
    match jit_alu32_load_store_aux hd lsr with
    | Some lsr0 => jit_alu32_load_store tl lsr0
    | None => None
    end
  end.

Definition jit_alu32_use_IR11_aux (ins: bpf_instruction): bool :=
  match ins with
  | BPF_BINARY a bop _ src =>
    match a with
    | A32 =>
      match src with
      | inl r => false
      | inr i =>
        match bop with
        | BPF_ADD | BPF_SUB | BPF_OR | BPF_AND | BPF_XOR | BPF_MOV =>
          if (Int.cmp Cle Int.zero i) && (Int.cmp Cle i (Int.repr 255)) then
            false
          else
            true
        | BPF_MUL => true
        | BPF_DIV | BPF_LSH | BPF_RSH | BPF_MOD| BPF_ARSH => false
        end
      end
    | A64 => false
    end
  | _ => false
  end.


Fixpoint jit_alu32_use_IR11 (l: list bpf_instruction): bool :=
  match l with
  | [] => false
  | hd :: tl =>
    if jit_alu32_use_IR11_aux hd then
      true
    else
      jit_alu32_use_IR11 tl
  end.

Definition jit_alu32_imm (imm32: int) (bop: binOp) (dst: ireg): option (list instruction) :=
  if (Int.cmp Cle Int.zero imm32) && (Int.cmp Cle imm32 (Int.repr 255)) then
    match bop with
    | BPF_ADD => Some [Padd dst dst (SOimm imm32)]
    | BPF_SUB => Some [Psub dst dst (SOimm imm32)]
    | BPF_MUL => Some [Pmovw IR11 imm32; Pmul dst dst IR11] (**r CompCert: only mul_reg *)
    | BPF_OR  => Some [Porr dst dst (SOimm imm32)]
    | BPF_AND => Some [Pand dst dst (SOimm imm32)]
    | BPF_XOR => Some [Peor dst dst (SOimm imm32)]
    | BPF_MOV => Some [Pmovw dst imm32]
    | _ => None
    end
  else
    let hi_32 := decode_arm32 imm32 16 16 in
      if Int.eq hi_32 Int.zero then
        match bop with
        | BPF_ADD => Some [Pmovw IR11 imm32; Padd dst dst (SOreg IR11)]
        | BPF_SUB => Some [Pmovw IR11 imm32; Psub dst dst (SOreg IR11)]
        | BPF_MUL => Some [Pmovw IR11 imm32; Pmul dst dst IR11]
        | BPF_OR  => Some [Pmovw IR11 imm32; Porr dst dst (SOreg IR11)]
        | BPF_AND => Some [Pmovw IR11 imm32; Pand dst dst (SOreg IR11)]
        | BPF_XOR => Some [Pmovw IR11 imm32; Peor dst dst (SOreg IR11)]
        | BPF_MOV => Some [Pmovw dst imm32]
        | _ => None
        end
      else
        let lo_32 := decode_arm32 imm32 0 16 in
          match bop with
          | BPF_ADD => Some [Pmovw IR11 lo_32; Pmovt IR11 hi_32; Padd dst dst (SOreg IR11)]
          | BPF_SUB => Some [Pmovw IR11 lo_32; Pmovt IR11 hi_32; Psub dst dst (SOreg IR11)]
          | BPF_MUL => Some [Pmovw IR11 lo_32; Pmovt IR11 hi_32; Pmul dst dst IR11]
          | BPF_OR  => Some [Pmovw IR11 lo_32; Pmovt IR11 hi_32; Porr dst dst (SOreg IR11)]
          | BPF_AND => Some [Pmovw IR11 lo_32; Pand dst dst (SOreg IR11)]
          | BPF_XOR => Some [Pmovw IR11 lo_32; Peor dst dst (SOreg IR11)]
          | BPF_MOV => Some [Pmovw IR11 lo_32; Pmovt IR11 hi_32; Pmov dst (SOreg IR11)]
          | _ => None
          end
    .

Definition jit_alu32 (ins: bpf_instruction): option (list instruction) :=
  match ins with
  | BPF_BINARY a bop dst src =>
    match a with
    | A32 =>
      match bop with
      | BPF_ADD =>
        match src with
        | inl r => Some [Padd (ireg_of_reg dst) (ireg_of_reg dst) (SOreg (ireg_of_reg r))]
        | inr i => jit_alu32_imm i BPF_ADD (ireg_of_reg dst)
        end
      | BPF_SUB =>
        match src with
        | inl r => Some [Psub (ireg_of_reg dst) (ireg_of_reg dst) (SOreg (ireg_of_reg r))]
        | inr i => jit_alu32_imm i BPF_SUB (ireg_of_reg dst)
        end
      | BPF_MUL =>
        match src with
        | inl r => Some [Pmul (ireg_of_reg dst) (ireg_of_reg dst) (ireg_of_reg r)]
        | inr i => jit_alu32_imm i BPF_MUL (ireg_of_reg dst)
        end
      | BPF_DIV =>
        match src with
        | inl r =>
          if (reg_eqb dst R0) && (reg_eqb r R1) then
            Some [Pudiv]
          else
            None
        | inr i => None
        end
      | BPF_OR =>
        match src with
        | inl r => Some [Porr (ireg_of_reg dst) (ireg_of_reg dst) (SOreg (ireg_of_reg r))]
        | inr i => jit_alu32_imm i BPF_OR (ireg_of_reg dst)
        end
      | BPF_AND =>
        match src with
        | inl r => Some [Pand (ireg_of_reg dst) (ireg_of_reg dst) (SOreg (ireg_of_reg r))]
        | inr i => jit_alu32_imm i BPF_AND (ireg_of_reg dst)
        end
      | BPF_LSH =>
        match src with
        | inl r => Some [Plsl (ireg_of_reg dst) (ireg_of_reg dst) (ireg_of_reg r)]
        | inr i => None
        end
      | BPF_RSH =>
        match src with
        | inl r => Some [Plsr (ireg_of_reg dst) (ireg_of_reg dst) (ireg_of_reg r)]
        | inr i => None
        end
      | BPF_MOD => None
      | BPF_XOR =>
        match src with
        | inl r => Some [Peor (ireg_of_reg dst) (ireg_of_reg dst) (SOreg (ireg_of_reg r))]
        | inr i => jit_alu32_imm i BPF_XOR (ireg_of_reg dst)
        end
      | BPF_MOV =>
        match src with
        | inl r => Some [Pmov (ireg_of_reg dst) (SOreg (ireg_of_reg r))]
        | inr i => jit_alu32_imm i BPF_MOV (ireg_of_reg dst)
        end
      | BPF_ARSH =>
        match src with
        | inl r => Some [Pasr (ireg_of_reg dst) (ireg_of_reg dst) (ireg_of_reg r)]
        | inr i => None
        end
      end
    | A64 => None
    end
  | _ => None
  end.

Fixpoint jit_core (l: list bpf_instruction): option (list instruction) :=
  match l with
  | [] => Some []
  | hd :: tl =>
    match jit_alu32 hd with
    | Some l0 =>
      match jit_core tl with
      | Some l1 => Some (l0 ++ l1)
      | None => None
      end
    | None => None
    end
  end.

Definition jit_spilling_aux (r: reg) (lsr: LoadStoreRegs): list instruction :=
  if is_non_reg r lsr then
    []
  else
    [Pstr (ireg_of_reg r) IR13 (SOimm (Int.mul (Int.repr (id_of_reg r)) (Int.repr 4)))].

Definition jit_spilling (lsr: LoadStoreRegs) (use_IR11: bool): list instruction :=
  let l4  := jit_spilling_aux R4 lsr in
  let l5  := jit_spilling_aux R5 lsr in
  let l6  := jit_spilling_aux R6 lsr in
  let l7  := jit_spilling_aux R7 lsr in
  let l8  := jit_spilling_aux R8 lsr in
  let l9  := jit_spilling_aux R9 lsr in
  let l10 := jit_spilling_aux R10 lsr in
  let l11 := if use_IR11 then [Pstr IR11 IR13 (SOimm (Int.repr 44))] else [] in
    l4 ++ l5 ++ l6 ++ l7 ++ l8 ++ l9 ++ l10 ++ l11.

Definition jit_load_aux (r: reg) (lsr: LoadStoreRegs): list instruction :=
  if is_load_reg r lsr then
    [Pldr (ireg_of_reg r) IR12 (SOimm (Int.mul (Int.repr (id_of_reg r)) (Int.repr 8)))]
  else
    [].

Definition jit_load (lsr: LoadStoreRegs): list instruction :=
  let l0  := jit_load_aux R0 lsr in
  let l1  := jit_load_aux R1 lsr in
  let l2  := jit_load_aux R2 lsr in
  let l3  := jit_load_aux R3 lsr in
  let l4  := jit_load_aux R4 lsr in
  let l5  := jit_load_aux R5 lsr in
  let l6  := jit_load_aux R6 lsr in
  let l7  := jit_load_aux R7 lsr in
  let l8  := jit_load_aux R8 lsr in
  let l9  := jit_load_aux R9 lsr in
  let l10 := jit_load_aux R10 lsr in
    l0 ++ l1 ++ l2 ++ l3 ++ l4 ++ l5 ++ l6 ++ l7 ++ l8 ++ l9 ++ l10.

Definition jit_store_aux (r: reg) (lsr: LoadStoreRegs): list instruction :=
  if is_store_reg r lsr then
    [Pstr (ireg_of_reg r) IR12 (SOimm (Int.mul (Int.repr (id_of_reg r)) (Int.repr 8)))]
  else
    [].

Definition jit_store (lsr: LoadStoreRegs): list instruction :=
  let l0  := jit_store_aux R0 lsr in
  let l1  := jit_store_aux R1 lsr in
  let l2  := jit_store_aux R2 lsr in
  let l3  := jit_store_aux R3 lsr in
  let l4  := jit_store_aux R4 lsr in
  let l5  := jit_store_aux R5 lsr in
  let l6  := jit_store_aux R6 lsr in
  let l7  := jit_store_aux R7 lsr in
  let l8  := jit_store_aux R8 lsr in
  let l9  := jit_store_aux R9 lsr in
  let l10 := jit_store_aux R10 lsr in
    l0 ++ l1 ++ l2 ++ l3 ++ l4 ++ l5 ++ l6 ++ l7 ++ l8 ++ l9 ++ l10.

Definition jit_reloading_aux (r: reg) (lsr: LoadStoreRegs): list instruction :=
  if is_non_reg r lsr then
    []
  else
    [Pldr (ireg_of_reg r) IR13 (SOimm (Int.mul (Int.repr (id_of_reg r)) (Int.repr 4)))].

Definition jit_reloading (lsr: LoadStoreRegs) (use_IR11: bool): list instruction :=
  let l4  := jit_reloading_aux R4 lsr in
  let l5  := jit_reloading_aux R5 lsr in
  let l6  := jit_reloading_aux R6 lsr in
  let l7  := jit_reloading_aux R7 lsr in
  let l8  := jit_reloading_aux R8 lsr in
  let l9  := jit_reloading_aux R9 lsr in
  let l10 := jit_reloading_aux R10 lsr in
  let l11 := if use_IR11 then [Pstr IR11 IR13 (SOimm (Int.repr 44))] else [] in
    l4 ++ l5 ++ l6 ++ l7 ++ l8 ++ l9 ++ l10 ++ l11.

Definition jit_post: list instruction := [Pldr IR13 IR13 (SOimm Int.zero); Pbreg IR14].

Definition jit (l: list bpf_instruction): option (list instruction) :=
  match l with
  | [] => None
  | _ =>
    match jit_alu32_load_store l init_LoadStoreRegs with
    | Some lsr =>
      match jit_core l with
      | Some l_core =>
        let b := jit_alu32_use_IR11 l in
          Some (jit_pre ++ (jit_spilling lsr b) ++ (jit_load lsr) ++
                l_core ++
                (jit_store lsr) ++ (jit_reloading lsr b) ++ jit_post)
      | None => None
      end
    | None => None
    end
  end.

Example rbpf_alu32_example_0: list bpf_instruction :=
  [ BPF_BINARY A32 BPF_MOV R0 (inl R10);
    BPF_BINARY A32 BPF_SUB R10 (inr (Int.repr 16))].
(*
Compute (jit rbpf_alu32_example_0). *)

Example rbpf_alu32_example_1: list bpf_instruction :=
  [ BPF_BINARY A32 BPF_MOV R5 (inr (Int.repr 65535));
    BPF_BINARY A32 BPF_MOV R3 (inl R5)].
(*
Compute (jit rbpf_alu32_example_1). *)

Example rbpf_alu32_example_2: list bpf_instruction :=
  [ BPF_BINARY A32 BPF_MOV R0 (inl R2);
    BPF_BINARY A32 BPF_SUB R2 (inl R0);
    BPF_BINARY A32 BPF_MOV R4 (inl R1);
    BPF_BINARY A32 BPF_MOV R1 (inl R4);
    BPF_BINARY A32 BPF_ADD R1 (inr (Int.repr 2))].
(*
Compute (jit rbpf_alu32_example_2). *)

Example rbpf_alu32_example_3: list bpf_instruction :=
  [ BPF_BINARY A32 BPF_MOV R4 (inl R5);
    BPF_BINARY A32 BPF_AND R4 (inr (Int.repr 65535));
    BPF_BINARY A32 BPF_MOV R6 (inr (Int.repr 16));
    BPF_BINARY A32 BPF_MOV R0 (inl R5);
    BPF_BINARY A32 BPF_RSH R0 (inl R6);
    BPF_BINARY A32 BPF_MOV R5 (inl R4);
    BPF_BINARY A32 BPF_ADD R5 (inl R0);
    BPF_BINARY A32 BPF_MOV R4 (inl R3);
    BPF_BINARY A32 BPF_AND R4 (inr (Int.repr 65535));
    BPF_BINARY A32 BPF_MOV R6 (inr (Int.repr 16));
    BPF_BINARY A32 BPF_MOV R0 (inl R3);
    BPF_BINARY A32 BPF_RSH R0 (inl R6);
    BPF_BINARY A32 BPF_MOV R3 (inl R4);
    BPF_BINARY A32 BPF_ADD R3 (inl R0)].
(*
Compute (jit rbpf_alu32_example_3). *)

Example rbpf_alu32_example_4: list bpf_instruction :=
  [ BPF_BINARY A32 BPF_MOV R1 (inl R5);
    BPF_BINARY A32 BPF_AND R1 (inr (Int.repr 65535));
    BPF_BINARY A32 BPF_MOV R4 (inr (Int.repr 16));
    BPF_BINARY A32 BPF_RSH R5 (inl R4);
    BPF_BINARY A32 BPF_ADD R1 (inl R5);
    BPF_BINARY A32 BPF_MOV R0 (inl R3);
    BPF_BINARY A32 BPF_AND R0 (inr (Int.repr 65535));
    BPF_BINARY A32 BPF_MOV R2 (inr (Int.repr 16));
    BPF_BINARY A32 BPF_RSH R3 (inl R2);
    BPF_BINARY A32 BPF_ADD R0 (inl R3);
    BPF_BINARY A32 BPF_MOV R4 (inr (Int.repr 16));
    BPF_BINARY A32 BPF_LSH R0 (inl R4);
    BPF_BINARY A32 BPF_OR R0 (inl R1)].
(*
Compute (jit rbpf_alu32_example_4). *)


