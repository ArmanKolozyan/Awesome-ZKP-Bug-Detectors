# Awesome-ZKP-Bug-Detectors

A collection of awesome Zero-Knowledge Proof (ZKP) bug detection tools, including a high-level explanation of each tool’s technique. For further details, references to the corresponding research papers and/or code repositories are provided.

## Summary

| Tool           | Target | Analysis       | Explanation                       | Documentation                                                                             | Code |
| -------------- | ------ | -------------- | --------------------------------- | ----------------------------------------------------------------------------------------- | ---- |
| Circomspect    | Circom | Taint Analysis | [Circomspect](#circomspect)       | [blog](https://blog.trailofbits.com/2022/09/15/it-pays-to-be-circomspect/)                | [repository](https://github.com/trailofbits/circomspect)     |
| ZKAP           |        |                | [ZKAP](#zkap)                     | [paper](https://www.usenix.org/conference/usenixsecurity24/presentation/wen)              |      |
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
   - A **Constraint Map** is created, which includes `in → {tmp, out}`.

#### Use Case

Constraint Analysis provides important information for **Side-Effect Analysis**, which is explained further in this section.

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

#### **Use Case 1: Detecting Under-Constrained Signals**

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

#### **Use Case 2: Side-Effect Analysis**

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



---

## Picus

---

## Coda

---

## Signal Tagging
