include Makefile.config

SED := sed
CAT := cat
AWK := awk
COQC := coqc
#COQDEP := coqdep
OCAMLOPT := ocamlopt
COQMAKEFILE := coq_makefile
CP := cp
MV := mv
HEADACHE := headache

CC=gcc
ARMCC=arm-none-eabi-gcc
ARMDUMP=arm-none-eabi-objdump
ARMFLAGS=-mcpu=cortex-m4 -mfpu=fpv4-sp-d16
OFLAGS=-Os
CLIGHTGEN=clightgen
CLIGHTGEN32=$(CLIGHTGEN32DIR)/clightgen

THIS_FILE := $(lastword $(MAKEFILE_LIST))

COQEXTRAFLAGS := COQEXTRAFLAGS = '-w all,-extraction,-disj-pattern-notation'

OCAMLINCS := -I extr # -I src

DIRS := comm dxcomm model verifier isolation monadicmodel monadicmodel2 dxmodel clight clightlogic simulation equivalence example jit

COQINCLUDES := INSTALLDEFAULTROOT = comm "\n"
COQINCLUDES += $(foreach d, $(DIRS),-R $(d) bpf.$(d) "\n")
COQINCLUDES +=-R $(COMPCERTDIR) compcert

COQDEP="$(COQBIN)coqdep" -exclude-dir aarch64 -exclude-dir x86_64 -exclude-dir riscV -exclude-dir powerpc -exclude-dir x86_32 $(COQINCLUDES)

#COQC="$(COQBIN)coqc" -q $(COQINCLUDES) $(COQCOPTS)

proof: $(FILES:.v=.vo)


all:
	@echo $@
	@$(MAKE) comm
	@$(MAKE) dxcomm
	@$(MAKE) model
	@$(MAKE) verifier
	@$(MAKE) isolation
	@$(MAKE) monadicmodel
	@$(MAKE) concretemodel
	@$(MAKE) compile
	@$(MAKE) clightmodel
	@$(MAKE) clightlogic
	@$(MAKE) simulation
	@$(MAKE) equivalence
	@$(MAKE) dxverifier
	@$(MAKE) jit-verifier
	@$(MAKE) jit
	@$(MAKE) jit-clight
	@$(MAKE) jit-simulation
	@$(MAKE) jit-verification
	@$(MAKE) document

COMM= Flag.v LemmaNat.v LemmaInt.v ListAsArray.v rBPFAST.v rBPFMemType.v rBPFValues.v MemRegion.v Regs.v BinrBPF.v \
   State.v Monad.v rBPFMonadOp.v
   
DXCOMM= InfComp.v GenMatchable.v \
   CoqIntegers.v DxIntegers.v DxValues.v DxBinrBPF.v DxNat.v
   
MODEL= Syntax.v Decode.v Semantics.v Encode.v PrintrBPF.v
   
VERIFIER= comm/state.v comm/monad.v \
   synthesismodel/opcode_synthesis.v synthesismodel/verifier_synthesis.v \
   dxmodel/Dxopcode.v dxmodel/Dxstate.v dxmodel/Dxmonad.v dxmodel/Dxverifier.v dxmodel/verifier_dx.v dxmodel/verifier_TestMain.v dxmodel/verifier_ExtrMain.v
   
DXVERIFIER= clightmodel/verifier.v \
   simulation/VerifierSimulation.v simulation/VerifierRel.v \
   simulation/correct_bpf_verifier_eval_ins.v simulation/correct_bpf_verifier_eval_ins_len.v simulation/correct_is_dst_R0.v simulation/correct_is_well_dst.v \
   simulation/correct_is_well_src.v simulation/correct_is_well_jump.v simulation/correct_is_not_div_by_zero.v simulation/correct_is_not_div_by_zero64.v \
   simulation/correct_is_shift_range.v simulation/correct_is_shift_range64.v simulation/correct_bpf_verifier_get_opcode.v simulation/correct_bpf_verifier_get_offset.v \
   simulation/correct_bpf_verifier_opcode_alu32_imm.v simulation/correct_bpf_verifier_opcode_alu32_reg.v simulation/correct_bpf_verifier_opcode_alu64_imm.v \
   simulation/correct_bpf_verifier_opcode_alu64_reg.v simulation/correct_bpf_verifier_opcode_branch_imm.v simulation/correct_bpf_verifier_opcode_branch_reg.v \
   simulation/correct_bpf_verifier_opcode_load_imm.v simulation/correct_bpf_verifier_opcode_load_reg.v simulation/correct_bpf_verifier_opcode_store_imm.v \
   simulation/correct_bpf_verifier_opcode_store_reg.v simulation/correct_bpf_verifier_aux2.v simulation/correct_bpf_verifier_aux.v simulation/correct_bpf_verifier.v \
   property/equivalence.v property/invariant.v


MONADIC= Opcode.v rBPFInterpreter.v
   
DXMODEL= DxAST.v DxFlag.v DxOpcode.v IdentDef.v DxMemType.v DxMemRegion.v DxRegs.v \
    DxState.v DxMonad.v DxInstructions.v \
    Tests.v TestMain.v ExtrMain.v

CLIGHTLOGIC= clight_exec.v Clightlogic.v \
    CommonLib.v CommonLemma.v CorrectRel.v CommonLemmaNat.v

QUIV = equivalence1.v equivalence2.v \
    Relation3.v CheckMem2.v equivalence3.v

ISOLATION=CommonISOLib.v AlignChunk.v VerifierOpcode.v \
    RegsInv.v MemInv.v VerifierInv.v CheckMem.v StateInv.v \
    IsolationLemma.v Isolation1.v Isolation2.v

CONCRETE=ConcreteState.v rBPFMonadOp2.v rBPFInterpreter2.v

SIMULATION=MatchState.v InterpreterRel.v \
    correct_eval_pc.v correct_upd_pc.v correct_upd_pc_incr.v correct_eval_reg.v correct_upd_reg.v correct_eval_flag.v correct_upd_flag.v \
    correct_eval_mrs_num.v correct_eval_mrs_regions.v correct_load_mem.v correct_store_mem_reg.v correct_store_mem_imm.v \
    correct_eval_ins_len.v correct_eval_ins.v correct_cmp_ptr32_nullM.v correct_get_dst.v correct_get_src.v correct_get_mem_region.v \
    correct__bpf_get_call.v correct_exec_function.v  \
    correct_reg64_to_reg32.v correct_get_offset.v correct_get_immediate.v correct_eval_immediate.v correct_get_src64.v correct_get_src32.v \
    correct_get_opcode_ins.v correct_get_opcode_alu64.v correct_get_opcode_alu32.v correct_get_opcode_branch.v correct_get_opcode_mem_ld_imm.v \
    correct_get_opcode_mem_ld_reg.v correct_get_opcode_mem_st_imm.v correct_get_opcode_mem_st_reg.v correct_get_opcode.v \
    correct_get_add.v correct_get_sub.v correct_get_addr_ofs.v correct_get_start_addr.v correct_get_block_size.v correct_get_block_perm.v \
    correct_is_well_chunk_bool.v correct_check_mem_aux2.v correct_check_mem_aux.v correct_check_mem.v \
    correct_step_opcode_alu64.v correct_step_opcode_alu32.v correct_step_opcode_branch.v \
    correct_step_opcode_mem_ld_imm.v correct_step_opcode_mem_ld_reg.v correct_step_opcode_mem_st_reg.v correct_step_opcode_mem_st_imm.v \
    correct_step.v correct_bpf_interpreter_aux.v correct_bpf_interpreter.v

JIT= thumb/PrintThumb.v \
    thumb/Arm32Reg.v thumb/LoadStoreRegs.v thumb/KeyValue2.v thumb/ThumbEncode.v thumb/ThumbDecode.v \
    thumb/JITState.v thumb/ThumbInsOp.v thumb/ThumbJITOpcode.v thumb/ThumbJIT.v \
    iBPF/IMonadOp.v iBPF/ISemantics.v thumb/PrintJIT.v \
    monadicJIT/JITIdDef.v monadicJIT/JITNat.v
    #monadicJIT/DxJITNat.v monadicJIT/DxLoadStoreRegs.v monadicJIT/DxKeyValue2.v monadicJIT/DxArm32Reg.v \
    #monadicJIT/DxThumbInsOp.v monadicJIT/DxThumbJITOpcode.v \
    #monadicJIT/DxJITMonadState.v monadicJIT/JITMonadOp.v monadicJIT/DxJITMonad.v \
    #monadicJIT/DxMonadCommon.v monadicJIT/DxThumbJIT.v \
    #monadicJIT/DxiBPFInterpreter.v \
    #monadicJIT/JITTests.v monadicJIT/JITTestMain.v monadicJIT/JITExtrMain.v
    
JITVERIFIER= JITVerifier.v DxJITVerifier.v \
    JITverifier_dx.v JITverifier_TestMain.v JITverifier_ExtrMain.v
    
JITVERIFICATION= rBPFSemInd.v JITSimple.v \
    JITSimpleProof0.v JITSimpleProofCore.v JITSimpleProof.v
    
JITSIMULATION= BitfieldLemma.v
    #SimulationJIT.v SimulationJITExtension.v SimulationJITExtensionProof1.v SimulationJITExtensionProof2.v \
    #SimulationJITExtensionProof.v SimulationJITProof1.v

EXAMPLE= DebugExtraction.v Add_Reg.v Sub_Reg.v Fletcher32.v Fletcher32IBPFInterpreter.v Fletcher32InterpreterSimulatorCompCert.v Fletcher32InterpreterSimulator.v

COQCOMM = $(addprefix comm/, $(COMM))
COQDXCOMM = $(addprefix dxcomm/, $(DXCOMM))
COQMODEL =  $(addprefix model/, $(MODEL))
COQVERIFIER =  $(addprefix verifier/,  $(VERIFIER))
COQEMONADIC =  $(addprefix monadicmodel/, $(MONADIC))
COQDXMODEL =  $(addprefix dxmodel/, $(DXMODEL))
COQCONCRETE = $(addprefix monadicmodel2/, $(CONCRETE))
CLIGHTLOGICDIR =  $(addprefix clightlogic/, $(CLIGHTLOGIC))
PROOF = $(addprefix simulation/, $(SIMULATION))
COQEQUIV =  $(addprefix equivalence/, $(QUIV))
COQISOLATION = $(addprefix isolation/, $(ISOLATION))
COQDXVERIFIER= $(addprefix verifier/, $(DXVERIFIER))
COQJIT = $(addprefix jit/, $(JIT))
COQJITVERIFIER = $(addprefix jit/verifier/, $(JITVERIFIER))
COQJITSIMULATION = $(addprefix jit/simulation/, $(JITSIMULATION))
COQJITVERIFICATION = $(addprefix jit/verification/, $(JITVERIFICATION))

COQEXAMPLE = $(addprefix example/, $(EXAMPLE))

FILES=$(COQCOMM) $(COQDXCOMM) $(COQMODEL) $(COQVERIFIER) $(COQEMONADIC) $(COQDXMODEL) \
  $(COQCONCRETE) $(CLIGHTLOGICDIR) $(PROOF) $(COQEQUIV) $(COQISOLATION) $(COQDXVERIFIER)

depend: $(FILES)
	@echo "Analyzing Coq dependencies"
	@$(COQDEP) $^ > .depend

comm:
	@echo $@
	$(COQMAKEFILE) -f _CoqProject $(COQCOMM) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile

dxcomm:
	@echo $@
	$(COQMAKEFILE) -f _CoqProject $(COQDXCOMM) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile

verifier:
	@echo $@
	$(COQMAKEFILE) -f _CoqProject $(COQVERIFIER) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile
	$(CP) verifier_TestMain.ml verifier/dxmodel
	$(CP) verifier_TestMain.mli verifier/dxmodel
	
dxverifier:
	@echo $@
	cd verifier && $(MAKE) verifier-all
	$(COQMAKEFILE) -f _CoqProject $(COQDXVERIFIER) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile

model:
	@echo $@
	$(COQMAKEFILE) -f _CoqProject $(COQMODEL) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile

monadicmodel:
	@echo $@
	$(COQMAKEFILE) -f _CoqProject $(COQEMONADIC) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile

isolation:
	@echo $@
	$(COQMAKEFILE) -f _CoqProject $(COQISOLATION) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile

equivalence:
	@echo $@
	$(COQMAKEFILE) -f _CoqProject $(COQEQUIV) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile

compcertinfo:
	@echo $@
	$(COMPCERTSRCDIR)/tools/modorder $(COMPCERTSRCDIR)/.depend.extr cfrontend/PrintCsyntax.cmx | \
	    $(AWK) '{ delete paths ;                                                                 \
	              for(i = 1; i <= NF; i++) {                                                     \
	                 x = $$i ;                                                                   \
	                 sub("/[^/]*$$", "", x) ;                                                    \
	                 paths[x] = 1 ;                                                              \
	              }                                                                              \
	              for(p in paths) {                                                              \
	                 print "-I" ;                                                                \
	                 print "$(COMPCERTSRCDIR)/" p ;                                              \
	              }                                                                              \
	            }' > compcertsrc-I	
	$(COMPCERTSRCDIR)/tools/modorder $(COMPCERTSRCDIR)/.depend.extr cfrontend/PrintCsyntax.cmx | \
	    $(AWK) 'BEGIN { RS=" " } /cmx/ { gsub(".*/","") ; print }' > compcertcprinter-cmx-args
	$(OCAMLOPT) -args compcertsrc-I -a -args compcertcprinter-cmx-args -o compcertcprinter.cmxa
	$(OCAMLOPT) -args compcertsrc-I -a -args compcertcprinter-cmx-args -o compcertcprinter.a

compile:
	@echo $@
	$(COQMAKEFILE) -f _CoqProject $(COQDXMODEL) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile
	@$(MAKE) compcertinfo
	$(CP) TestMain.ml dxmodel
	$(CP) TestMain.mli dxmodel
	$(OCAMLOPT) -args $(DXDIR)/cprinter-inc-args -I dxmodel dxmodel/TestMain.mli	
	$(OCAMLOPT) -args $(DXDIR)/cprinter-inc-args -I dxmodel -c dxmodel/TestMain.ml
	$(OCAMLOPT) -args compcertsrc-I str.cmxa unix.cmxa compcertcprinter.cmxa $(DXDIR)/ResultMonad.cmx $(DXDIR)/DXModule.cmx $(DXDIR)/DumpAsC.cmx dxmodel/TestMain.cmx -o dxmodel/main
	ln -sf $(COMPCERTSRCDIR)/compcert.ini dxmodel/compcert.ini
	cd dxmodel && ./main
	$(MV) dxmodel/generated.c dxmodel/repatch
	cd dxmodel/repatch \
	&& $(CC) -o repatch1 ../../repatch/repatch1.c && ./repatch1 generated.c generated_repatch1.c && rm generated.c repatch1 \
	&& $(CC) -o repatch2 repatch2.c && ./repatch2 generated_repatch1.c generated_repatch2.c && rm generated_repatch1.c repatch2 \
	&& $(CC) -o repatch3 ../../repatch/repatch3.c && ./repatch3 generated_repatch2.c generated_repatch3.c && rm generated_repatch2.c repatch3 \
	&& $(CC) -o repatch4 ../../repatch/repatch4.c && ./repatch4 interpreter_pre.c generated_repatch3.c interpreter.c && rm generated_repatch3.c repatch4
	$(MV) dxmodel/repatch/interpreter.c clight

clightmodel:
	@echo $@
	cd clight && $(CC) -o $@ $(OFLAGS) fletcher32_bpf_test.c interpreter.c && ./$@
	cd clight && $(CLIGHTGEN32) interpreter.c
	$(COQMAKEFILE) -f _CoqProject clight/interpreter.v $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile

clightlogic:
	@echo $@
	$(COQMAKEFILE) -f _CoqProject $(CLIGHTLOGICDIR) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile

simulation:
	@echo $@
	$(COQMAKEFILE) -f _CoqProject $(PROOF) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile

concretemodel:
	@echo $@
	$(COQMAKEFILE) -f _CoqProject $(COQCONCRETE) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile	

jit:
	@echo $@
	$(COQMAKEFILE) -f _CoqProject $(COQJIT) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile
	$(CP) JITTestMain.ml jit/monadicJIT
	$(CP) JITTestMain.mli jit/monadicJIT
	$(OCAMLOPT) -args $(DXDIR)/cprinter-inc-args -I jit/monadicJIT jit/monadicJIT/JITTestMain.mli	
	$(OCAMLOPT) -args $(DXDIR)/cprinter-inc-args -I jit/monadicJIT -c jit/monadicJIT/JITTestMain.ml
	$(OCAMLOPT) -args compcertsrc-I str.cmxa unix.cmxa compcertcprinter.cmxa $(DXDIR)/ResultMonad.cmx $(DXDIR)/DXModule.cmx $(DXDIR)/DumpAsC.cmx jit/monadicJIT/JITTestMain.cmx -o jit/monadicJIT/main
	ln -sf $(COMPCERTSRCDIR)/compcert.ini jit/monadicJIT/compcert.ini
	cd jit/monadicJIT && ./main
	$(MV) jit/monadicJIT/jit_generated.c jit/monadicJIT/repatch
	cd jit/monadicJIT/repatch \
	&& $(CC) -o repatch1 ../../../repatch/repatch1.c && ./repatch1 jit_generated.c generated_repatch1.c && rm jit_generated.c repatch1 \
	&& $(CC) -o repatch2 repatch2.c && ./repatch2 generated_repatch1.c generated_repatch2.c && rm generated_repatch1.c repatch2 \
	&& $(CC) -o repatch3 ../../../repatch/repatch3.c && ./repatch3 generated_repatch2.c generated_repatch3.c && rm generated_repatch2.c repatch3 \
	&& $(CC) -o repatch4 ../../../repatch/repatch4.c && ./repatch4 ibpf_interpreter_pre.c generated_repatch3.c ibpf_interpreter.c && rm generated_repatch3.c repatch4
	$(MV) jit/monadicJIT/repatch/ibpf_interpreter.c jit/clight

jit-clight:
	@echo $@
	#cd jit/clight \
	#&& $(ARMCC) -o $@ $(OFLAGS) $(ARMFLAGS) fletcher32_ibpf_test.c ibpf_interpreter.c && ./$@ \
	cd jit/clight && $(CLIGHTGEN32) ibpf_interpreter.c
	$(COQMAKEFILE) -f _CoqProject jit/clight/ibpf_interpreter.v $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile

jit-verifier:
	@echo $@
	$(COQMAKEFILE) -f _CoqProject $(COQJITVERIFIER) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile
	$(CP) JITverifier_TestMain.ml jit/verifier
	$(CP) JITverifier_TestMain.mli jit/verifier
	$(OCAMLOPT) -args $(DXDIR)/cprinter-inc-args -I jit/verifier jit/verifier/JITverifier_TestMain.mli	
	$(OCAMLOPT) -args $(DXDIR)/cprinter-inc-args -I jit/verifier -c jit/verifier/JITverifier_TestMain.ml
	$(OCAMLOPT) -args compcertsrc-I str.cmxa unix.cmxa compcertcprinter.cmxa $(DXDIR)/ResultMonad.cmx $(DXDIR)/DXModule.cmx $(DXDIR)/DumpAsC.cmx jit/verifier/JITverifier_TestMain.cmx -o jit/verifier/main
	ln -sf $(COMPCERTSRCDIR)/compcert.ini jit/verifier/compcert.ini
	cd jit/verifier && ./main
	$(MV) jit/verifier/generated.c jit/verifier/repatch
	cd jit/verifier/repatch \
	&& $(CC) -o repatch1 ../../../repatch/repatch1.c && ./repatch1 generated.c generated_repatch1.c && rm generated.c repatch1 \
	&& $(CC) -o repatch2 repatch2.c && ./repatch2 generated_repatch1.c generated_repatch2.c && rm generated_repatch1.c repatch2 \
	&& $(CC) -o repatch3 ../../../repatch/repatch3.c && ./repatch3 generated_repatch2.c generated_repatch3.c && rm generated_repatch2.c repatch3 \
	&& $(CC) -o repatch4 ../../../repatch/repatch4.c && ./repatch4 jit_verifier_pre.c generated_repatch3.c jit_verifier.c && rm generated_repatch3.c repatch4
	$(MV) jit/verifier/repatch/jit_verifier.c jit/clight

jit-simulation:
	@echo $@
	$(COQMAKEFILE) -f _CoqProject $(COQJITSIMULATION) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile

jit-verification:
	@echo $@
	$(COQMAKEFILE) -f _CoqProject $(COQJITVERIFICATION) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile

example:
	@echo $@
	$(COQMAKEFILE) -f _CoqProject $(COQEXAMPLE) $(COQEXTRAFLAGS)  -o CoqMakefile
	make -f CoqMakefile

DOCFLAG := -external https://compcert.org/doc/html compcert -base bpf -short-names 
document:
	@echo $@
	mkdir -p html
	mkdir -p html/glob
	cp clight/*.glob html/glob
	cp clightlogic/*.glob html/glob
	cp comm/*.glob html/glob
	cp dxcomm/*.glob html/glob
	cp dxmodel/*.glob html/glob
	cp equivalence/*.glob html/glob
	cp model/*.glob html/glob
	cp monadicmodel/*.glob html/glob
	cp simulation/*.glob html/glob
	cp isolation/*.glob html/glob
	cp verifier/clightmodel/*.glob html/glob
	cp verifier/comm/*.glob html/glob
	cp verifier/dxmodel/*.glob html/glob
	cp verifier/property/*.glob html/glob
	cp verifier/simulation/*.glob html/glob
	cp verifier/synthesismodel/*.glob html/glob
	cp jit/thumb/*.glob html/glob
	cp jit/iBPF/*.glob html/glob
	cp jit/monadicJIT/*.glob html/glob
	coq2html $(DOCFLAG) -d html html/glob/*.glob clight/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob clightlogic/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob comm/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob dxcomm/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob dxmodel/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob equivalence/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob model/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob monadicmodel/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob simulation/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob isolation/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob verifier/clightmodel/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob verifier/comm/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob verifier/dxmodel/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob verifier/property/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob verifier/simulation/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob verifier/synthesismodel/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob jit/thumb/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob jit/iBPF/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob jit/monadicJIT/*.v
	coq2html $(DOCFLAG) -d html html/glob/*.glob jit/verifier/*.v

CoqProject:
	@echo $(COQINCLUDES) > _CoqProject

addheadache:
	@echo $@
	$(HEADACHE) -c head_config -h head \
	clightlogic/*.v comm/*.v dxcomm/*.v dxmodel/*.v dxmodel/repatch/*.c \
	equivalence/*.v isolation/*.v \
	example/*.v example/*.ml example/exampleCode/*.c \
	jit/*/*.v \
	model/*.v monadicmodel/*.v monadicmodel2/*.v simulation/*.v \
	verifier/*/*.v verifier/dxmodel/repatch/*.c

clean :
	@echo $@
	make -f CoqMakefile clean
	find . -name "*\.vo" -exec rm {} \;
	find . -name "*\.vok" -exec rm {} \;
	find . -name "*\.vos" -exec rm {} \;
	find . -name "*\.glob" -exec rm {} \;
	find . -name "*\.aux" -exec rm {} \;
	find . -name "*\.cmi" -exec rm {} \;
	find . -name "*\.cmx" -exec rm {} \;
	find . -name "*\.crashcoqide" -exec rm {} \;


# We want to keep the .cmi that were built as we go
.SECONDARY:

.PHONY: all test comm dxcomm verifier dxverifier model monadicmodel isolation equivalence compcertinfo compile extract clightmodel clightlogic simulation jit jit-clight jit-verifier jit-simulation example clean addheadache
