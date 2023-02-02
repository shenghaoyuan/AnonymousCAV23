include ../Makefile.config

SED := sed
CAT := cat
AWK := awk
COQC := coqc
COQDEP := coqdep
OCAMLOPT := ocamlopt
COQMAKEFILE := coq_makefile
CP := cp
MV := mv

CC=gcc
OFLAGS=-Os
CLIGHTGEN=clightgen
CLIGHTGEN32=$(CLIGHTGEN32DIR)/clightgen


verifier-all:
	@echo $@
	@$(MAKE) verifier-extract
	@$(MAKE) verifier-clightmodel

verifier-extract:
	@echo $@
	$(OCAMLOPT) -args $(DXDIR)/cprinter-inc-args -I dxmodel dxmodel/verifier_TestMain.mli	
	$(OCAMLOPT) -args $(DXDIR)/cprinter-inc-args -I dxmodel -c dxmodel/verifier_TestMain.ml
	$(OCAMLOPT) -args ../compcertsrc-I -a -args ../compcertcprinter-cmx-args -o compcertcprinter.a
	$(OCAMLOPT) -args ../compcertsrc-I str.cmxa unix.cmxa ../compcertcprinter.cmxa $(DXDIR)/ResultMonad.cmx $(DXDIR)/DXModule.cmx $(DXDIR)/DumpAsC.cmx dxmodel/verifier_TestMain.cmx -o dxmodel/main
	ln -sf $(COMPCERTSRCDIR)/compcert.ini dxmodel/compcert.ini
	cd dxmodel && ./main
	$(MV) dxmodel/generated.c dxmodel/repatch
	cd dxmodel/repatch \
	&& $(CC) -o repatch1 ../../../repatch/repatch1.c && ./repatch1 generated.c generated_repatch1.c && rm generated.c repatch1 \
	&& $(CC) -o repatch2 repatch2.c && ./repatch2 generated_repatch1.c generated_repatch2.c && rm generated_repatch1.c repatch2 \
	&& $(CC) -o repatch3 ../../../repatch/repatch3.c && ./repatch3 generated_repatch2.c generated_repatch3.c && rm generated_repatch2.c repatch3 \
	&& $(CC) -o repatch4 ../../../repatch/repatch4.c && ./repatch4 verifier_pre.c generated_repatch3.c verifier.c && rm generated_repatch3.c repatch4
	$(MV) dxmodel/repatch/verifier.c clightmodel

verifier-clightmodel:
	@echo $@
	cd clightmodel && $(CC) -o $@ $(OFLAGS) fletcher32_verifier_test.c verifier.c && ./$@
	cd clightmodel && $(CLIGHTGEN32) verifier.c

.PHONY: verifier-all verifier-extract verifier-clightmodel
