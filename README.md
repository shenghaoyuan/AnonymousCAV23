# HAVM: A Verified Hybrid eBPF VM/JIT for Micro-controllers

This repository contains the version of HAVM presented in the CAV23 submission #.

## HAVM Overview

HAVM consists of:
- A **JIT_ALU** compiler translating rBPF ALU32 instructions into ARM binary (THUMB ISA);
- A hybird interpreter combining a existing [verified rBPF interpreter](https://gitlab.inria.fr/syuan/rbpf-dx/-/tree/CAV22-AE) and a glue code.

## Project Structure

The whole project is based on the verified rBPF interpreter, we add the following components:

- A refined rBPF interpreter (`/monadicmodel2`) and 
- its refinement proof (`/equivalence`)
  + `CheckMem2.v`, 
  + `equivalence3.v`, and 
  + `Relation3.v`
- the JIT_ALU32 compiler and the hybrid interpreter (`/jit`)
  + the compiler in Coq `/jit/thumb` 
  + the interpreter in Coq `/jit/iBPF` 
  + HAVM dx model in Coq `/jit/monadicJIT` 
  + HAVM in C `/jit/clight` 
  + JIT proof `/jit/verification`
  + interpreter proof `/jit/simulation`
  + A new verifier to support CompCert-related limitations checking.
  
## Installation
Following the instructions from the verified rBPF interpreter.

**To avoid any potential issues, we provide a html version of compiled project. (see `/html`)**

## Build of HAVM

```shell
cd /YOUR-PATH/HAVM
./configure --opamprefixdir=YOUR-OPAM-DIR --compcertbindir=YOUR-CompCertBin-DIR
# e.g. `./configure --opamprefixdir=/YOUR-PATH/.opam/4.11.1 --compcertbindir=/YOUR-PATH/CompCertBin`
make all # you could always `make clean` firstly to get a clean environment
```
# Benchmarks and Experiments
Following the instructions from the verified rBPF interpreter, you then add `/benchmark.../` to RIOT-OS and perform the experiments.
