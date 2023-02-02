From Coq Require Import ZArith Lia.
From compcert Require Import Integers Values AST Memory Memdata.

From bpf.comm Require Import ListAsArray Flag Regs State Monad BinrBPF rBPFMonadOp rBPFMemType rBPFValues.

From  bpf.monadicmodel Require Import Opcode.
From bpf.monadicmodel2 Require Import ConcreteState rBPFInterpreter2.

From bpf.jit.thumb Require Import ThumbJITOpcode JITState ThumbJIT.
From bpf.jit.iBPF Require Import ISemantics.
From bpf.jit.simulation Require Import SimulationJIT SimulationJITExtension SimulationJITExtensionProof1 SimulationJITExtensionProof2.

Section SimulationJITProof.
  Context {flag_blk regs_blk jit_blk: block}.

  Theorem bpf_interpreter_sim_ibpf_interpreter:
    forall f sti0 st_i1 stj0 stj st_a res
      (Hbefore: Rel flag_blk regs_blk jit_blk sti0 stj0 st_a)
      (Hex: RelEx flag_blk regs_blk jit_blk sti0 stj0)
      (Hex0 : RelEx flag_blk regs_blk jit_blk sti0 stj) (*
      (Hjit: jit_alu32 stj0 = Some stj) *)
      (Hst: bpf_interpreter f sti0 = Some (res, st_i1)),
        exists stj1,
          ibpf_interpreter f stj = Some (res, stj1) /\
          Rel flag_blk regs_blk jit_blk st_i1 stj1 st_a.
  Proof.
    unfold bpf_interpreter, ibpf_interpreter.
    unfold bindM, returnM.
    induction f.
    - intros.
      simpl in *. (*
      eapply jit_alu32_preserves_extension in Hjit; eauto. *)

      unfold rBPFMonadOp2.upd_flag in Hst.
      unfold IMonadOp.upd_jit_flag.
      destruct upd_flag eqn: Hupd_flag; [| inversion Hst].
      eapply upd_flag_extension with (f := BPF_ILLEGAL_LEN) in Hex0; eauto.
      destruct Hex0 as (st1' & Hsome & Hex0).
      rewrite Hsome; clear Hsome.

      unfold rBPFMonadOp2.eval_flag in Hst.
      unfold IMonadOp.eval_jit_flag.
      destruct eval_flag eqn: Heval_flag; [| inversion Hst].
      eapply eval_flag_extension in Heval_flag; eauto.
      rewrite Heval_flag; clear Heval_flag.
      destruct comp_eq_32.
      + unfold rBPFMonadOp2.eval_reg in Hst.
        unfold IMonadOp.eval_jit_reg.
        destruct eval_reg eqn: Heval_reg; [| inversion Hst].
        eapply eval_reg_extension in Heval_reg; eauto.
        rewrite Heval_reg; clear Heval_reg.
        exists st1'.
        inversion Hst.
        subst.
        split; [reflexivity | ].
        eapply RelEx_implies_Rel in Hex0; eauto.

      + inversion Hst.
        subst.
        exists st1'.
        split; [reflexivity | ].
        eapply RelEx_implies_Rel in Hex0; eauto.

    - intros.
      simpl in Hst.
      simpl.
      unfold bindM, returnM in *.
      unfold rBPFMonadOp2.eval_ins_len in Hst.
      unfold IMonadOp.eval_jit_ins_len.
      unfold rBPFMonadOp2.eval_pc in Hst.
      unfold IMonadOp.eval_jit_pc.

      unfold eval_pc in Hst.
      unfold eval_jit_pc.
      assert (Heq_pc: pc_loc sti0 = jit_pc stj). {
        clear - Hex0.
        eapply eval_pc_extension; eauto.
      }
      rewrite Heq_pc in Hst.

      unfold eval_ins_len in Hst.
      unfold eval_jit_ins_len.
      assert (Heq_len: ins_len sti0 = jit_ins_len stj). {
        clear - Hex0.
        erewrite eval_ins_len_extension; eauto.
      }
      rewrite Heq_len in Hst.

      destruct Int.ltu eqn: Hlt.
      + unfold step in Hst.
        unfold ibpf_step.
        unfold bindM, returnM in *.
        unfold rBPFMonadOp2.eval_pc in Hst.
        unfold IMonadOp.eval_jit_pc.
        unfold eval_pc in Hst.
        unfold eval_jit_pc.
        rewrite Heq_pc in Hst.

        unfold rBPFMonadOp2.eval_ins in Hst.
        unfold IMonadOp.eval_jit_ins.
        rewrite Heq_len in Hst.

        unfold Int.cmpu in *.
        rewrite Hlt in *; clear Hlt.

        unfold eval_ins in Hst.
        unfold eval_jit_ins.
        (**r we must say (ins sti0) = (jit_ins stj) *)
        assert (Heq_ins: ins sti0 = jit_ins stj). {
          clear - Hex0.
          erewrite eval_ins_extension; eauto.
        }
        rewrite Heq_ins in Hst.
        destruct List64AsArray.index eqn: Hins; [| inversion Hst].
        unfold rBPFInterpreter2.get_opcode_ins in Hst.
        unfold get_opcode_ins.
        unfold returnM in *.
        unfold rBPFInterpreter2.get_opcode in Hst.
        unfold get_opcode.
        unfold returnM in *.
        unfold rBPFInterpreter2.get_dst in Hst.
        unfold get_dst.
        unfold rBPFMonadOp2.int64_to_dst_reg in Hst.
        unfold IMonadOp.int64_to_dst_reg.
        destruct int64_to_dst_reg'; [ | inversion Hst].

        unfold rBPFInterpreter2.get_src64 in Hst.
        unfold get_src64.
        unfold rBPFInterpreter2.reg64_to_reg32, rBPFInterpreter2.get_src32 in Hst.
        unfold reg64_to_reg32, get_src32.
        unfold rBPFInterpreter2.reg64_to_reg32 in Hst.
        unfold reg64_to_reg32.
        unfold rBPFInterpreter2.get_src in Hst.
        unfold get_src.
        unfold rBPFMonadOp2.int64_to_src_reg in Hst.
        unfold IMonadOp.int64_to_src_reg.
        unfold rBPFInterpreter2.get_immediate in Hst.
        unfold get_immediate.
        unfold rBPFInterpreter2.eval_immediate in Hst.
        unfold eval_immediate.
        unfold rBPFMonadOp2.eval_reg in Hst.
        unfold IMonadOp.eval_jit_reg.
        unfold rBPFInterpreter2.get_offset in Hst.
        unfold rBPFInterpreter2.get_addr_ofs in Hst.
        unfold bindM, returnM in *.
        { destruct byte_to_opcode.
          -(**r ALU64 *)
            destruct eval_reg eqn: Heval_reg; [| inversion Hst].
            eapply eval_reg_extension in Heval_reg; eauto.
            rewrite Heval_reg; clear Heval_reg.
            destruct Int.eq.
            + destruct step_opcode_alu64 eqn: Halu64; [| inversion Hst].
              destruct p.
              eapply step_opcode_alu64_some_tt in Halu64 as Halu64_eq; eauto.
              subst u.
              eapply step_opcode_alu64_sim in Halu64; eauto.
              destruct Halu64 as (stj1 & Halu64_eq & Hex1).
              rewrite Halu64_eq; clear Halu64_eq.

              clear Heq_pc Heq_len Heq_ins.

              unfold rBPFMonadOp2.eval_flag in Hst.
              unfold IMonadOp.eval_jit_flag.
              destruct eval_flag eqn: Heval_flag; [| inversion Hst].
              eapply eval_flag_extension in Heval_flag; eauto.
              rewrite Heval_flag; clear Heval_flag.
              destruct comp_eq_32 eqn: Heq_v0.
              * assert (Heq_pc: pc_loc s = jit_pc stj1). {
                  clear - Hex1.
                  eapply eval_pc_extension; eauto.
                }
                rewrite Heq_pc in Hst.

                assert (Heq_len: ins_len s = jit_ins_len stj1). {
                  clear - Hex1.
                  erewrite eval_ins_len_extension; eauto.
                }
                rewrite Heq_len in Hst.
                destruct Int.ltu eqn: Hlt.
                { unfold rBPFMonadOp2.upd_pc_incr in Hst.
                  unfold IMonadOp.upd_jit_pc_incr.
                  rewrite Heq_pc, Heq_len in Hst.
                  destruct Int.cmpu; [| inversion Hst].
                  assert (Hex2: RelEx flag_blk regs_blk jit_blk (upd_pc_incr s) (upd_jit_pc_incr stj1)). {
                    eapply upd_pc_incr_extension; eauto.
                  }
                  eapply IHf with (sti0 := upd_pc_incr s) (stj0 := upd_jit_pc_incr stj1); eauto.
                  eapply RelEx_implies_Rel; eauto.
                }
                { unfold rBPFMonadOp2.upd_flag in Hst.
                  unfold IMonadOp.upd_jit_flag.
                  destruct upd_flag eqn: Hupd_flag; [| inversion Hst].
                  eapply upd_flag_extension with (f := BPF_ILLEGAL_LEN) in Hupd_flag as Hupd_jit_flag; eauto.
                  destruct Hupd_jit_flag as (stj2 & Hupd_jit_flag & Hex2).
                  rewrite Hupd_jit_flag.
                  destruct eval_flag eqn: Heval_flag; [| inversion Hst].
                  eapply eval_flag_extension in Heval_flag; eauto.
                  rewrite Heval_flag; clear Heval_flag.
                  destruct (comp_eq_32 v1 _) eqn: Heq_v1.
                  - destruct eval_reg eqn: Heval_reg; [| inversion Hst].
                    eapply eval_reg_extension in Heval_reg; eauto.
                    rewrite Heval_reg.
                    inversion Hst; subst.
                    exists stj2.
                    split; [reflexivity | eapply RelEx_implies_Rel; eauto].
                  - inversion Hst; subst.
                    exists stj2.
                    split; [reflexivity | eapply RelEx_implies_Rel; eauto].
                }
              * destruct eval_flag eqn: Heval_flag; [| inversion Hst].
                eapply eval_flag_extension in Heval_flag; eauto.
                rewrite Heval_flag; clear Heval_flag.
                destruct (comp_eq_32 v1 _) eqn: Heq_v1.
                { destruct eval_reg eqn: Heval_reg; [| inversion Hst].
                  eapply eval_reg_extension in Heval_reg; eauto.
                  rewrite Heval_reg; clear Heval_reg.

                  inversion Hst.
                  subst.
                  exists stj1.
                  split; [reflexivity | ].
                  eapply RelEx_implies_Rel in Hex1; eauto.
                }
                { inversion Hst; subst.
                  exists stj1; split; [reflexivity | eapply RelEx_implies_Rel in Hex1; eauto ].
                }
            + destruct int64_to_src_reg'; [| inversion Hst].
              destruct eval_reg eqn: Heval_reg; [| inversion Hst].
              eapply eval_reg_extension in Heval_reg; eauto.
              rewrite Heval_reg; clear Heval_reg.

              destruct step_opcode_alu64 eqn: Halu64; [| inversion Hst].
              destruct p.
              eapply step_opcode_alu64_some_tt in Halu64 as Halu64_eq; eauto.
              subst u.
              eapply step_opcode_alu64_sim in Halu64; eauto.
              destruct Halu64 as (stj1 & Halu64_eq & Hex1).
              rewrite Halu64_eq; clear Halu64_eq.

              clear Heq_pc Heq_len Heq_ins.

              unfold rBPFMonadOp2.eval_flag in Hst.
              unfold IMonadOp.eval_jit_flag.
              destruct eval_flag eqn: Heval_flag; [| inversion Hst].
              eapply eval_flag_extension in Heval_flag; eauto.
              rewrite Heval_flag; clear Heval_flag.
              destruct comp_eq_32 eqn: Heq_v0.
              * assert (Heq_pc: pc_loc s = jit_pc stj1). {
                  clear - Hex1.
                  eapply eval_pc_extension; eauto.
                }
                rewrite Heq_pc in Hst.

                assert (Heq_len: ins_len s = jit_ins_len stj1). {
                  clear - Hex1.
                  erewrite eval_ins_len_extension; eauto.
                }
                rewrite Heq_len in Hst.
                destruct Int.ltu eqn: Hlt.
                { unfold rBPFMonadOp2.upd_pc_incr in Hst.
                  unfold IMonadOp.upd_jit_pc_incr.
                  rewrite Heq_pc, Heq_len in Hst.
                  destruct Int.cmpu; [| inversion Hst].
                  assert (Hex2: RelEx flag_blk regs_blk jit_blk (upd_pc_incr s) (upd_jit_pc_incr stj1)). {
                    eapply upd_pc_incr_extension; eauto.
                  }
                  eapply IHf with (sti0 := upd_pc_incr s) (stj0 := upd_jit_pc_incr stj1); eauto.
                  eapply RelEx_implies_Rel; eauto.
                }
                { unfold rBPFMonadOp2.upd_flag in Hst.
                  unfold IMonadOp.upd_jit_flag.
                  destruct upd_flag eqn: Hupd_flag; [| inversion Hst].
                  eapply upd_flag_extension with (f := BPF_ILLEGAL_LEN) in Hupd_flag as Hupd_jit_flag; eauto.
                  destruct Hupd_jit_flag as (stj2 & Hupd_jit_flag & Hex2).
                  rewrite Hupd_jit_flag.
                  destruct eval_flag eqn: Heval_flag; [| inversion Hst].
                  eapply eval_flag_extension in Heval_flag; eauto.
                  rewrite Heval_flag; clear Heval_flag.
                  destruct (comp_eq_32 v2 _) eqn: Heq_v2.
                  - destruct eval_reg eqn: Heval_reg; [| inversion Hst].
                    eapply eval_reg_extension in Heval_reg; eauto.
                    rewrite Heval_reg.
                    inversion Hst; subst.
                    exists stj2.
                    split; [reflexivity | eapply RelEx_implies_Rel; eauto].
                  - inversion Hst; subst.
                    exists stj2.
                    split; [reflexivity | eapply RelEx_implies_Rel; eauto].
                }
              * destruct eval_flag eqn: Heval_flag; [| inversion Hst].
                eapply eval_flag_extension in Heval_flag; eauto.
                rewrite Heval_flag; clear Heval_flag.
                destruct (comp_eq_32 v2 _) eqn: Heq_v2.
                { destruct eval_reg eqn: Heval_reg; [| inversion Hst].
                  eapply eval_reg_extension in Heval_reg; eauto.
                  rewrite Heval_reg; clear Heval_reg.

                  inversion Hst.
                  subst.
                  exists stj1.
                  split; [reflexivity | ].
                  eapply RelEx_implies_Rel in Hex1; eauto.
                }
                { inversion Hst; subst.
                  exists stj1; split; [reflexivity | eapply RelEx_implies_Rel in Hex1; eauto ].
                }
          - (**r ALU32 *)
            destruct eval_reg; [| inversion Hst].
            destruct Int.eq.
            + destruct step_opcode_alu32 eqn: Halu32; [| inversion Hst].
              destruct p.
              eapply step_opcode_alu32_some_tt in Halu32 as Halu32_eq; eauto.
              subst u.
              admit.
            + destruct int64_to_src_reg'; [| inversion Hst].
              destruct eval_reg eqn: Heval_reg; [| inversion Hst].

              destruct step_opcode_alu32 eqn: Halu32; [| inversion Hst].
              destruct p.
              eapply step_opcode_alu32_some_tt in Halu32 as Halu32_eq; eauto.
              subst u.
              admit.
          - (**r Branch *)
            destruct eval_reg eqn: Heval_reg; [| inversion Hst].
            eapply eval_reg_extension in Heval_reg; eauto.
            rewrite Heval_reg; clear Heval_reg.
            unfold get_offset, returnM.
            destruct Int.eq.
            + destruct step_opcode_branch eqn: Hbranch; [| inversion Hst].
              destruct p.
              eapply step_opcode_branch_some_tt in Hbranch as Hbranch_eq; eauto.
              subst u.
              eapply step_opcode_branch_sim in Hbranch; eauto.
              destruct Hbranch as (stj1 & Hbranch_eq & Hex1).
              unfold Val.longofint, sint32_to_vint.
              rewrite Hbranch_eq; clear Hbranch_eq.

              unfold rBPFMonadOp2.eval_flag in Hst.
              unfold IMonadOp.eval_jit_flag.
              destruct eval_flag eqn: Heval_flag; [| inversion Hst].
              eapply eval_flag_extension in Heval_flag; eauto.
              rewrite Heval_flag; clear Heval_flag.
              clear Heq_pc Heq_len Heq_ins.
              destruct comp_eq_32 eqn: Heq_v0.
              * assert (Heq_pc: pc_loc s = jit_pc stj1). {
                  clear - Hex1.
                  eapply eval_pc_extension; eauto.
                }
                rewrite Heq_pc in Hst.

                assert (Heq_len: ins_len s = jit_ins_len stj1). {
                  clear - Hex1.
                  erewrite eval_ins_len_extension; eauto.
                }
                rewrite Heq_len in Hst.
                destruct Int.ltu eqn: Hlt.
                { unfold rBPFMonadOp2.upd_pc_incr in Hst.
                  unfold IMonadOp.upd_jit_pc_incr.
                  rewrite Heq_pc, Heq_len in Hst.
                  destruct Int.cmpu; [| inversion Hst].
                  assert (Hex2: RelEx flag_blk regs_blk jit_blk (upd_pc_incr s) (upd_jit_pc_incr stj1)). {
                    eapply upd_pc_incr_extension; eauto.
                  }
                  eapply IHf with (sti0 := upd_pc_incr s) (stj0 := upd_jit_pc_incr stj1); eauto.
                  eapply RelEx_implies_Rel; eauto.
                }
                { unfold rBPFMonadOp2.upd_flag in Hst.
                  unfold IMonadOp.upd_jit_flag.
                  destruct upd_flag eqn: Hupd_flag; [| inversion Hst].
                  eapply upd_flag_extension with (f := BPF_ILLEGAL_LEN) in Hupd_flag as Hupd_jit_flag; eauto.
                  destruct Hupd_jit_flag as (stj2 & Hupd_jit_flag & Hex2).
                  rewrite Hupd_jit_flag.
                  destruct eval_flag eqn: Heval_flag; [| inversion Hst].
                  eapply eval_flag_extension in Heval_flag; eauto.
                  rewrite Heval_flag; clear Heval_flag.
                  destruct (comp_eq_32 v1 _) eqn: Heq_v1.
                  - destruct eval_reg eqn: Heval_reg; [| inversion Hst].
                    eapply eval_reg_extension in Heval_reg; eauto.
                    rewrite Heval_reg.
                    inversion Hst; subst.
                    exists stj2.
                    split; [reflexivity | eapply RelEx_implies_Rel; eauto].
                  - inversion Hst; subst.
                    exists stj2.
                    split; [reflexivity | eapply RelEx_implies_Rel; eauto].
                }
              * destruct eval_flag eqn: Heval_flag; [| inversion Hst].
                eapply eval_flag_extension in Heval_flag; eauto.
                rewrite Heval_flag; clear Heval_flag.
                destruct (comp_eq_32 v1 _) eqn: Heq_v1.
                { destruct eval_reg eqn: Heval_reg; [| inversion Hst].
                  eapply eval_reg_extension in Heval_reg; eauto.
                  rewrite Heval_reg; clear Heval_reg.

                  inversion Hst.
                  subst.
                  exists stj1.
                  split; [reflexivity | ].
                  eapply RelEx_implies_Rel in Hex1; eauto.
                }
                { inversion Hst; subst.
                  exists stj1; split; [reflexivity | eapply RelEx_implies_Rel in Hex1; eauto ].
                }
            + destruct int64_to_src_reg'; [| inversion Hst].
              destruct eval_reg eqn: Heval_reg; [| inversion Hst].
              eapply eval_reg_extension_vlong in Heval_reg as Hreg_vl; eauto.
              destruct Hreg_vl as (vl & Hreg_vl).
              subst v0.
              eapply eval_reg_extension in Heval_reg; eauto.
              rewrite Heval_reg; clear Heval_reg.

              destruct step_opcode_branch eqn: Hbranch; [| inversion Hst].
              destruct p.
              eapply step_opcode_branch_some_tt in Hbranch as Hbranch_eq; eauto.
              subst u.
              eapply step_opcode_branch_sim in Hbranch; eauto.
              destruct Hbranch as (stj1 & Hbranch_eq & Hex1).
              rewrite Hbranch_eq; clear Hbranch_eq.

              clear Heq_pc Heq_len Heq_ins.

              unfold rBPFMonadOp2.eval_flag in Hst.
              unfold IMonadOp.eval_jit_flag.
              destruct eval_flag eqn: Heval_flag; [| inversion Hst].
              eapply eval_flag_extension in Heval_flag; eauto.
              rewrite Heval_flag; clear Heval_flag.
              destruct comp_eq_32 eqn: Heq_v0.
              * assert (Heq_pc: pc_loc s = jit_pc stj1). {
                  clear - Hex1.
                  eapply eval_pc_extension; eauto.
                }
                rewrite Heq_pc in Hst.

                assert (Heq_len: ins_len s = jit_ins_len stj1). {
                  clear - Hex1.
                  erewrite eval_ins_len_extension; eauto.
                }
                rewrite Heq_len in Hst.
                destruct Int.ltu eqn: Hlt.
                { unfold rBPFMonadOp2.upd_pc_incr in Hst.
                  unfold IMonadOp.upd_jit_pc_incr.
                  rewrite Heq_pc, Heq_len in Hst.
                  destruct Int.cmpu; [| inversion Hst].
                  assert (Hex2: RelEx flag_blk regs_blk jit_blk (upd_pc_incr s) (upd_jit_pc_incr stj1)). {
                    eapply upd_pc_incr_extension; eauto.
                  }
                  eapply IHf with (sti0 := upd_pc_incr s) (stj0 := upd_jit_pc_incr stj1); eauto.
                  eapply RelEx_implies_Rel; eauto.
                }
                { unfold rBPFMonadOp2.upd_flag in Hst.
                  unfold IMonadOp.upd_jit_flag.
                  destruct upd_flag eqn: Hupd_flag; [| inversion Hst].
                  eapply upd_flag_extension with (f := BPF_ILLEGAL_LEN) in Hupd_flag as Hupd_jit_flag; eauto.
                  destruct Hupd_jit_flag as (stj2 & Hupd_jit_flag & Hex2).
                  rewrite Hupd_jit_flag.
                  destruct eval_flag eqn: Heval_flag; [| inversion Hst].
                  eapply eval_flag_extension in Heval_flag; eauto.
                  rewrite Heval_flag; clear Heval_flag.
                  destruct (comp_eq_32 v1 _) eqn: Heq_v1.
                  - destruct eval_reg eqn: Heval_reg; [| inversion Hst].
                    eapply eval_reg_extension in Heval_reg; eauto.
                    rewrite Heval_reg.
                    inversion Hst; subst.
                    exists stj2.
                    split; [reflexivity | eapply RelEx_implies_Rel; eauto].
                  - inversion Hst; subst.
                    exists stj2.
                    split; [reflexivity | eapply RelEx_implies_Rel; eauto].
                }
              * destruct eval_flag eqn: Heval_flag; [| inversion Hst].
                eapply eval_flag_extension in Heval_flag; eauto.
                rewrite Heval_flag; clear Heval_flag.
                destruct (comp_eq_32 v1 _) eqn: Heq_v1.
                { destruct eval_reg eqn: Heval_reg; [| inversion Hst].
                  eapply eval_reg_extension in Heval_reg; eauto.
                  rewrite Heval_reg; clear Heval_reg.

                  inversion Hst.
                  subst.
                  exists stj1.
                  split; [reflexivity | ].
                  eapply RelEx_implies_Rel in Hex1; eauto.
                }
                { inversion Hst; subst.
                  exists stj1; split; [reflexivity | eapply RelEx_implies_Rel in Hex1; eauto ].
                }
          - (**r MEM_LD_IMM *)
            
          - (**r MEM_LD_IMM *) ...
          all: admit.
        }
      + unfold rBPFMonadOp2.upd_flag in Hst.
        unfold IMonadOp.upd_jit_flag.
        destruct upd_flag eqn: Hupd_flag; [| inversion Hst].

        eapply upd_flag_extension with (f := BPF_ILLEGAL_LEN) in Hex0; eauto.
        destruct Hex0 as (st1' & Hsome & Hex0).
        rewrite Hsome; clear Hsome.
        unfold rBPFMonadOp2.eval_flag in Hst.
        unfold IMonadOp.eval_jit_flag.
        destruct eval_flag eqn: Heval_flag; [| inversion Hst].
        eapply eval_flag_extension in Heval_flag as Hsome; eauto.
        rewrite Hsome; clear Hsome.

        destruct comp_eq_32 eqn: Hsucc.
        * unfold rBPFMonadOp2.eval_reg in Hst.
          unfold IMonadOp.eval_jit_reg.
          destruct eval_reg eqn: Heval_reg; [| inversion Hst].
          eapply eval_reg_extension in Heval_reg as Hsome; eauto.
          inversion Hst.
          subst.
          rewrite Hsome; clear Hsome.
          exists st1'.
          split; [reflexivity | ].
          eapply RelEx_implies_Rel in Hex0; eauto.
        * inversion Hst.
          subst.
          exists st1'.
          split; [reflexivity | ].
          eapply RelEx_implies_Rel in Hex0; eauto.
  Admitted.
End SimulationJITProof.