# Awesome-ZKP-Bug-Detectors

A collection of awesome Zero-Knowledge Proof (ZKP) bug detection tools, including a high-level explanation of each tool’s technique. For further details, references to the corresponding research papers and/or code repositories are provided.

## Summary

| Tool           | Target | Analysis       | Explanation                       | Documentation                                                                             | Code |
| -------------- | ------ | -------------- | --------------------------------- | ----------------------------------------------------------------------------------------- | ---- |
| Circomspect    | Circom | Taint Analysis | [Circomspect](#circomspect)       | [blog](https://blog.trailofbits.com/2022/09/15/it-pays-to-be-circomspect/)                | [repository](https://github.com/trailofbits/circomspect)     |  
| ZKAP           | Circom       |   Semantic Pattern Matching             | [ZKAP](#zkap)                     | [paper](https://www.usenix.org/conference/usenixsecurity24/presentation/wen)              | [repository](https://github.com/whbjzzwjxq/ZKAP)     |
| Picus          |        |                | [Picus](#picus)                   | [paper](https://dl.acm.org/doi/10.1145/3591282)                                           |      |
| Coda           |        |                | [Coda](#coda)                     | [paper](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a078/1RjEaNkBQIg) |      |
| Signal Tagging |        |                | [Signal Tagging](#signal-tagging) | [docs](https://docs.circom.io/circom-language/tags/)                                      |      |

## Circomspect

Circomspect is a static analyzer and linter for Circom. It performs multiple analysis passes to detect issues like unused and under-constrained signals.
For a list of all the analysis passes, please refer to the [official documentation](https://github.com/trailofbits/circomspect/blob/ece9efe0a21e6c422a43ab6f2e1c0ce99678013b/doc/analysis_passes.md).
Below, we focus on the two main analysis techniques: Constraint Analysis and Taint Analysis.

### 1. Constraint Analysis

Constraint Analysis is implemented in [`constraint_analysis.rs`](https://github.com/trailofbits/circomspect/blob/main/program_analysis/src/constraint_analysis.rs). The goal is to build a _Constraint Map_, which tracks how signals (variables) in the circuit are related through constraints. It maps a variable to other variables that it influences through constraints. Such a map is useful because it enables the identification of variables that impact critical elements, such as output signals.

#### Key Steps

1. **Single-Step Constraints**:
   - Captures direct constraints between variables, such as `a === b + c`.
2. **Multi-Step Constraints**:
   - Computes transitive relationships between variables. For example:
     - If `a === b + c` and `b === d`, then `a` is transitively constrained by `d`.

#### Example

```circom
template T(n) {
    signal input in;
    signal output out;
    signal tmp;

    tmp <== 2 * in;  // 'tmp' is constrained by 'in'
    out <== in * in; // 'out' is constrained by 'in'
}
```

- **Constraints**:
   - `tmp <== 2 * in`: Adds a direct constraint between `in` and `tmp`.
   - `out <== in * in`: Adds a direct constraint between `in` and `out`.
- **Result**:
   - A *Constraint Map* is created, which includes `in → {tmp, out}`.

#### Use Case

Constraint Analysis provides important information for *Side-Effect Analysis*, which is explained further in this section.

### 2. Taint Analysis

Taint analysis differs from constraint analysis in that it focuses on the flow of data through the program, rather than just the constraints themselves.
Taint analysis thus also considers constructs like *substitutions* (`<--`), where written variables are tainted by the variables they depend on, and *conditional branches* (`if-then-else`), where a variable used in a non-constant condition taints all variables assigned within the conditional body. 

Taint Analysis is implemented in [`taint_analysis.rs`](https://github.com/trailofbits/circomspect/blob/main/program_analysis/src/taint_analysis.rs).
It tracks how values propagate through the circuit via a _Taint Map_. That map is used to ensure all constraints and outputs are correctly influenced by inputs or other constrained variables.

#### Key Steps

1. **Taint Mapping**:

   - Tracks direct relationships between signals. For example, given `tmp <-- x`, we can conclude that `x` taints `tmp`.

2. **Propagation**:

   - Determines indirect relationships. If `x` taints `tmp` and `tmp` taints `y`, then `x` indirectly taints `y`.

#### Example

```circom
template TaintExample(m, n) {
            component right[m];
            for (var i = 0; i < n; i++) {
                right[i] = 0;
            }
        }
```


- `m` taints `right` since `right` is declared as an `m` dimensional array. 
- `n` taints `i` since the update `i++` depends on the condition `i < n`
- `n` taints `right` since `right[i] = 0` depends on on the condition `i < n`

#### Use Case 1: Detecting Under-Constrained Signals

Taint analysis is used to ensure intermediate signals are sufficiently constrained. 
A signal must participate in at least two constraints: one defining its value and another restricting or using it. If not, it is flagged as under-constrained.

Example:

```circom
template Test(n) {
    signal input a;
    signal b;
    signal output c;

    c <== 2 * a;  // 'b' is declared but unused
}
```

`b` is flagged as under-constrained because it does not propagate into any constraints. 

No underconstrained signals are present in this example:
```circom
template Test(n) {
              signal input a;
              signal b;
              signal output c;

              b <== a * a;
              c <== a * b; // b is used here
            }
```            

#### Use Case 2: Side-Effect Analysis

Side-effect analysis identifies side-effect-free local variables and intermediate signals. Specifically, a variable is flagged as side-effect free if it does not flow into:

1. An input or output signal.
2. A function return value.
3. A constraint restricting an input or output signal.

This ensures that all computations in the circuit contribute to witness or constraint generation.

Example:

```circom
template SideEffectFree() {
    signal input x;
    signal y;
    signal output z;

    y <== x + 1;  // 'y' is side-effect free
    z <== x * 2;
}
```
`y` is flagged as side-effect free because its value does not propagate to outputs or constraints.

In side-effect analysis, *taint analysis* is used to compute the set of variables tainted by input and output signals, forming an initial set of *sinks*. *Constraint analysis* then identifies variables that participate in constraints involving these sinks. It ensures that any variable that directly or indirectly constrains input or output sinks is included in the final set of "important" variables. 
Both analyses are essential: taint analysis captures the flow of data, while constraint analysis verifies structural dependencies.

---

## ZKAP

ZKAP is a static analysis framework developed to enhance the security of Circom circuits. 
ZKAP identifies a wide range of vulnerabilities, including:

1. *Unconstrained Signals*: Input or output signals that are not sufficiently constrained, either by constants or by input dependencies. Examples include:
   - **Unconstrained Circuit Outputs (UCO)**: Outputs that are neither constrained to constants nor depend transitively on inputs.  
   - **Unconstrained Sub-Circuit Inputs (USCI)**: Inputs to components that are expected to be constrained externally but are not, leading to potential misuse.

2. *Semantic Mismatches*: Discrepancies between the circuit's data flow (computational logic) and its constraint logic. This category includes:  
   - **Dataflow-Constraint Discrepancies (DCD)**: Cases where a signal depends on another during witness computation but is not properly constrained by it, causing inconsistencies between computation and verification.  
   - **Type Mismatch (TM)**: Instances where the witness calculation and constraints enforce different expectations for a signal’s type, such as mismatched range checks.

3. *Improper Component Use*: Issues arising from incorrect or incomplete usage of circuit components, which can introduce security flaws, including:
   - **Unconstrained Sub-Circuit Outputs (USCO)**: Component outputs that do not influence the calling circuit due to missing constraints at the call site.  
   - **Assignment Misuse (AM)**: Using `<--` for assignments where `<==` (constraint operator) is required.  
   - **Non-Deterministic Dataflow (NDD)**: Conditional assignments based on signals (and not on template variables), which are prone to errors.  

4. *Critical Errors in Arithmetic Logic*: Vulnerabilities specific to the arithmetic handling of signals:
   - **Division-by-Zero (DBZ)**: Division expressions that are dependent on input signals without proper constraints, causing computation-constraint divergence.  

5. *Warnings for Potentially Problematic Patterns*:  
   - **Unconstrained Signals (US)**: Flags unconstrained intermediate signals which, while not always a bug, could signal potential inefficiencies or vulnerabilities.


### Analysis Technique

#### Circuit Dependence Graph (CDG)

ZKAP uses a *Circuit Dependence Graph (CDG)* to model the internal relationships within Circom circuits. The CDG incorporates:

- **Computational Data Flow**: Traces the propagation of data through assignments, computations, and signal dependencies.  
- **Constraint Logic**: Models how signals are constrained and interrelated.

Each CDG node represents a signal or constant, while edges encode:

1. *Data Flow Dependencies*: Indicate how signals are influenced by others through computations or assignments, which can be derived from the assignment operators (e.g., `<--` and `<==`)
2. *Constraint Dependencies*: Represent signals appearing in the same constraint, which can be derived from the constraint operators (e.g., `===` and `<==`)

At a high level, a data flow edge from *v* to *u* labeled by *s* indicates that the value of *u* directly depends on *v* due to an
assignment to *u* of an expression *s* containing *v*. Similarly, a constraint edge between *u* and *v* labeled *s* indicates that there is an equation *s* directly relating *u* and *v*.
(The above description is wrong in the paper, I corrected it here.)

#### Vulnerability Description Language (VDL)

ZKAP introduces the *Vulnerability Description Language (VDL)*, allowing users to define vulnerability patterns at the semantic level over the CDG representation.

##### How VDL Works

1. **Custom Patterns**: VDL allows users to describe, in Datalog-like syntax, vulnerabilities as patterns in the CDG, such as unconstrained outputs or mismatches between input signals and constraints.  
2. **Semantic Matching**: ZKAP matches these patterns against the CDG to detect issues, such as *Unconstrained Circuit Outputs (UCO)* or *Dataflow-Constraint Discrepancies (DCD)*.  

##### Example

A VDL pattern to identify *Unconstrained Circuit Outputs (UCO)* could be:
```vdlang
sigDep(v) :- sig(u), cEdge+(u,v)
isConst(v) :- cEdge+(u,v), const(u), !sigDep(v)
inDep(v) :- in(u), cEdge+(u,v)
UCO(v) :- out(v), !isConst(v), !inDep(v)
```
This anti-pattern specification introduces three auxiliary predicates:

1. **`sigDep(v)`**: This predicate indicates that `v` is dependent on some other signal.  
2. **`isConst(v)`**: This predicate evaluates to `true` if `v` is only dependent on a constant, meaning it must be constrained to a constant.  
3. **`inDep(v)`**: This predicate checks whether `v` is dependent on an input signal.  

Using these predicates, an output signal is classified as unconstrained if it is neither:  
- (a) constrained to be a constant, nor  
- (b) dependent on an input signal. 

### Key Features

1. *Predefined Detectors*: ZKAP includes nine predefined vulnerability checkers.

2. *High Precision and Recall*: ZKAP’s semantic approach minimises false positives and negatives, achieving superior precision (82.4%) and recall (96.6%).  

3. *Evaluation*: Tested on *258 Circom circuits* across 17 projects, ZKAP identified *32 previously unknown vulnerabilities*.

---

## Picus

---

## Coda

---

## Signal Tagging
