# Awesome-ZKP-Bug-Detectors

A collection of awesome Zero-Knowledge Proof (ZKP) bug detection tools, including a high-level explanation of each tool’s technique. For further details, references to the corresponding research papers and/or code repositories are provided.

## Summary

| Tool           | Target   | Analysis                  | Explanation                       | Documentation                                                                             | Code                                                     |
| -------------- | -------- | ------------------------- | --------------------------------- | ----------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| Circomspect    | Circom   | Taint Analysis            | [Circomspect](#circomspect)       | [blog](https://blog.trailofbits.com/2022/09/15/it-pays-to-be-circomspect/)                | [repository](https://github.com/trailofbits/circomspect) |
| ZKAP           | Circom   | Semantic Pattern Matching | [ZKAP](#zkap)                     | [paper](https://www.usenix.org/conference/usenixsecurity24/presentation/wen)              | [repository](https://github.com/whbjzzwjxq/ZKAP)         |
| Picus          | R1CS | UCP & SMT                 | [Picus](#picus)                   | [paper](https://dl.acm.org/doi/10.1145/3591282)                                           | [repository](https://github.com/Veridise/Picus)          |
| Coda           | Custom Functional Language (using Coq)         |  Refinement Types                         | [Coda](#coda)                     | [paper](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a078/1RjEaNkBQIg) |   [repository](https://github.com/Veridise/coda)                                                       |
| Signal Tagging |          |                           | [Signal Tagging](#signal-tagging) | [docs](https://docs.circom.io/circom-language/tags/)                                      |                                                          |

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
  - A _Constraint Map_ is created, which includes `in → {tmp, out}`.

#### Use Case

Constraint Analysis provides important information for _Side-Effect Analysis_, which is explained further in this section.

### 2. Taint Analysis

Taint analysis differs from constraint analysis in that it focuses on the flow of data through the program, rather than just the constraints themselves.
Taint analysis thus also considers constructs like _substitutions_ (`<--`), where written variables are tainted by the variables they depend on, and _conditional branches_ (`if-then-else`), where a variable used in a non-constant condition taints all variables assigned within the conditional body.

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

In side-effect analysis, _taint analysis_ is used to compute the set of variables tainted by input and output signals, forming an initial set of _sinks_. _Constraint analysis_ then identifies variables that participate in constraints involving these sinks. It ensures that any variable that directly or indirectly constrains input or output sinks is included in the final set of "important" variables.
Both analyses are essential: taint analysis captures the flow of data, while constraint analysis verifies structural dependencies.

---

## ZKAP

ZKAP is a static analysis framework developed to enhance the security of Circom circuits.
ZKAP identifies a wide range of vulnerabilities, including:

1. _Unconstrained Signals_: Input or output signals that are not sufficiently constrained, either by constants or by input dependencies. Examples include:

   - **Unconstrained Circuit Outputs (UCO)**: Outputs that are neither constrained to constants nor depend transitively on inputs.
   - **Unconstrained Sub-Circuit Inputs (USCI)**: Inputs to components that are expected to be constrained externally but are not, leading to potential misuse.

2. _Semantic Mismatches_: Discrepancies between the circuit's data flow (computational logic) and its constraint logic. This category includes:

   - **Dataflow-Constraint Discrepancies (DCD)**: Cases where a signal depends on another during witness computation but is not properly constrained by it, causing inconsistencies between computation and verification.
   - **Type Mismatch (TM)**: Instances where the witness calculation and constraints enforce different expectations for a signal’s type, such as mismatched range checks.

3. _Improper Component Use_: Issues arising from incorrect or incomplete usage of circuit components, which can introduce security flaws, including:

   - **Unconstrained Sub-Circuit Outputs (USCO)**: Component outputs that do not influence the calling circuit due to missing constraints at the call site.
   - **Assignment Misuse (AM)**: Using `<--` for assignments where `<==` (constraint operator) is required.
   - **Non-Deterministic Dataflow (NDD)**: Conditional assignments based on signals (and not on template variables), which are prone to errors.

4. _Critical Errors in Arithmetic Logic_: Vulnerabilities specific to the arithmetic handling of signals:

   - **Division-by-Zero (DBZ)**: Division expressions that are dependent on input signals without proper constraints, causing computation-constraint divergence.

5. _Warnings for Potentially Problematic Patterns_:
   - **Unconstrained Signals (US)**: Flags unconstrained intermediate signals which, while not always a bug, could signal potential inefficiencies or vulnerabilities.

### Analysis Technique

#### Circuit Dependence Graph (CDG)

ZKAP uses a _Circuit Dependence Graph (CDG)_ to model the internal relationships within Circom circuits. The CDG incorporates:

- **Computational Data Flow**: Traces the propagation of data through assignments, computations, and signal dependencies.
- **Constraint Logic**: Models how signals are constrained and interrelated.

Each CDG node represents a signal or constant, while edges encode:

1. _Data Flow Dependencies_: Indicate how signals are influenced by others through computations or assignments, which can be derived from the assignment operators (e.g., `<--` and `<==`)
2. _Constraint Dependencies_: Represent signals appearing in the same constraint, which can be derived from the constraint operators (e.g., `===` and `<==`)

At a high level, a data flow edge from _v_ to _u_ labeled by _s_ indicates that the value of _u_ directly depends on _v_ due to an
assignment to _u_ of an expression _s_ containing _v_. Similarly, a constraint edge between _u_ and _v_ labeled _s_ indicates that there is an equation _s_ directly relating _u_ and _v_.
(The above description is wrong in the paper, I corrected it here.)

#### Vulnerability Description Language (VDL)

ZKAP introduces the _Vulnerability Description Language (VDL)_, allowing users to define vulnerability patterns at the semantic level over the CDG representation.

##### How VDL Works

1. **Custom Patterns**: VDL allows users to describe, in Datalog-like syntax, vulnerabilities as patterns in the CDG, such as unconstrained outputs or mismatches between input signals and constraints.
2. **Semantic Matching**: ZKAP matches these patterns against the CDG to detect issues, such as _Unconstrained Circuit Outputs (UCO)_ or _Dataflow-Constraint Discrepancies (DCD)_.

##### Example

A VDL pattern to identify _Unconstrained Circuit Outputs (UCO)_ could be:

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

1. _Predefined Detectors_: ZKAP includes nine predefined vulnerability checkers.

2. _High Precision and Recall_: ZKAP’s semantic approach minimises false positives and negatives, achieving superior precision (82.4%) and recall (96.6%).

3. _Evaluation_: Tested on 258 Circom circuits* across 17 projects, ZKAP identified \_32 previously unknown vulnerabilities*.

---

## Picus

Picus is a language-agnostic tool designed to detect under-constrained circuits given polynomial equations generated by the compiler (rather than Circom programs
themselves). It combines **lightweight static analysis (Uniqueness Constraint Propagation)** and **SMT-based reasoning** to identify whether all output variables in a circuit are fully constrainedy.

### Analysis Technique

#### 1. Uniqueness Constraint Propagation (UCP)

UCP is a static analysis phase that iteratively propagates constraints through the circuit to determine whether each output variable is uniquely defined by the inputs. It relies on three core inference rules: **Var**, **Const**, and **Op**.

##### Inference Rules

1. **Var Rule**:

   - Any variable in the set _K_ (the set of already-proven constrained variables) is considered constrained. This rule provides the starting point for UCP, where _K_ typically includes input variables and other explicitly constrained signals.

2. **Const Rule**:

   - Constants are inherently constrained because their values are fixed and independent of other variables.

3. **Op Rule**:
   - If a more complex expression _e_ is defined as _e1_ $\oplus$ _e2_, where $\oplus$ is an arithmetic or logical operator (e.g., addition, multiplication), then _e_ is constrained if both _e1_ and _e2_ are constrained.

In addition to the basic rules, Picus employs more complex inference rules to handle intricate relationships between variables. One important example is the **Assign Rule**:

- If the circuit contains an equation of the form $c \cdot x - e = 0$, and:
  - _e_ is inferred to be constrained.
  - $c \neq 0$ (a non-zero constant).
- Then, _x_ can also be inferred to be constrained because the equation can be rewritten as $x = c^{-1} \cdot e$

##### How UCP Propagates Constraints

1. **Initial Assumptions**:

   - UCP begins with a set _K_, which contains variables that are already known to be constrained. Typically, this set includes:
     - Input variables, as they are externally provided and fixed.
     - Constants, which are inherently constrained.

2. **Recursive Application of Rules**:
   - UCP applies rules such as the _Op_ rule to propagate constraints through the circuit: <br/>
      If _e1_ and _e2_ are constrained, their combined result _e = e1_ $\oplus$ _e2_ is also constrained.

##### Limitations

The paper explicitly states that **UCP alone cannot solve all under-constrained problems** because it cannot identify **pairs of witnesses** that demonstrate under-constrained behavior.

Thus, the SMT solver complements UCP by addressing these limitations.

#### 2. SMT Solver

When UCP cannot constrain all variables, Picus invokes an SMT solver to formally verify the uniqueness of remaining variables.

##### How the SMT Solver Works:

1. **Duplicate Circuit Representation**:

   - To verify whether a variable _v_ is constrained, Picus encodes **two copies of the circuit**:
     - The first copy uses the original variables _V_.
     - The second copy uses a duplicate set of variables _V'_.
   - The SMT solver is tasked with determining whether any two satisfying assignments that agree on the input variables also agree on 𝑣 (i.e., v = v').

2. **Strengthening with Constrained Variables**:

   - Variables that have already been proven constrained by UCP (belonging to the set _K_) are used to strengthen the query. Specifically: <br/>
     For each _u_ $\in$ _K_, the SMT query adds a condition _u = u'_.

3. **SMT Query Formulation**:

   - The SMT solver is given the following query:
     - $\Phi \land \Phi' \land \bigwedge_{u \in K} (u = u') \implies (v = v')$,
       where:
       - $\Phi$: The circuit's constraints with the original variables _V_.
       - $\Phi'$: The circuit's constraints with the duplicate variables _V'_.
       - $\bigwedge_{u \in K} (u = u')$: Strengthening conditions for variables already proven constrained.
     - The solver verifies whether this implication holds. If true, _v_ is uniquely constrained.

4. **Encoding Value Information**:
   - Picus incorporates **interval-based constraints** to further simplify the SMT query. For each variable _w_, its possible values are partitioned into intervals _(l, u)_, so that the solver checks only valid ranges: <br/>
   For example, if _w_ can take values in the range _[1, 10]_, the solver includes constraints $1 \leq w \leq 10$.
   - These intervals are encoded as disjunctions for efficiency, allowing the SMT solver to focus on feasible solutions.

#### 3. Value Inference

Value inference is used to narrow the possible values for variables in the circuit. This information is for example leveraged during SMT-based reasoning to simplify queries and improve efficiency. Rules like the **Assign Rule** and **Op Rule** are used for this.

##### Assign Rule

The **Assign Rule** is applied when a circuit contains an equation of the form:

$c \cdot x - e = 0 \quad \text{where} \quad c \neq 0.$

When we rearrange the equation to isolate _x_, we get:
$x = c^{-1} \cdot e$

This implies that the possible values for _x_ are derived by multiplying the values of _e_ by the inverse of _c_.

##### Op Rule

If:

1. _e1_ has a set of possible values $\Omega_1$,
2. _e2_ has a set of possible values $\Omega_2$,

Then:

$e1 \oplus e2$ has a set of possible values:
$\{v1 \oplus v2 \mid (v1, v2) \in \Omega_1 \times \Omega_2\}$

This means that the possible values of $e1 \oplus e2$ are obtained by applying the operator $\oplus$ to all pairs _(v1, v2)_ where $v1 \in \Omega_1$ and $v2 \in \Omega_2$.

### Integration of UCP and SMT Solver

Picus combines UCP and SMT reasoning in an iterative process:

1. UCP initially identifies constrained variables.
2. If variables remain unconstrained, SMT queries are generated for verification.
3. Results from the SMT solver update the set of constrained variables, enabling further propagation by UCP.

This iterative process continues until:

- All outputs are verified as constrained.
- A counterexample to uniqueness of a query variable 𝑞, which corresponds to an output of the circuit, is found.
- No further progress can be made.

---

## Coda

CODA is a domain-specific **statically typed functional programming language** tailored for building and verifying ZKP circuits. Unlike traditional DSLs for ZKP, such as Circom, CODA incorporates a powerful refinement type system that allows for formal specification and verification of correctness properties. 
This ensures the arithmetic circuits match their intended functionality and reduces the likelihood of errors.

#### Refinement Types

Refinement types are an enhancement over basic types. They embed logical constraints to ensure values conform to specific properties. A refinement type is expressed as `{T | P}`, where:

- **T**: The base type, such as an integer or field element.
- **P**: A predicate specifying additional constraints on the type.

**Example:**
```
{ν : F | ν > 0}
```
This type denotes a field element that is strictly positive.

### Key Steps

1. **Specification**: Developers annotate their programs with refinement types to specify expected behaviours, such as range checks or structural invariants.

2. **Type Checking**: The CODA compiler validates the program against its refinement types. It generates logical obligations (lemmas) ensuring that the implementation satisfies its specification.

3. **Proof Obligations**: The lemmas are checked using Coq, a proof assistant. In some cases, manual intervention may be required.

4. **Compilation**: Once all proofs are complete, CODA compiles the program into a Rank-1 Constraint System (R1CS). It is important to note that the R1CS generated by CODA is no different from the R1CS generated for the same program (but without refinement types) written in Circom.

### Example: BigLessThan Circuit

This example implements a circuit that computes whether one binary-encoded number (`a`) is less than another binary-encoded number (`b`). It uses refinement types to ensure correctness.

```coda
circuit BigLessThan
(k: {Z | 0 <= v})              // Number of bits
(a: {F | binary v}^k)          // Binary-encoded number `a`
(b: {F | binary v}^k)          // Binary-encoded number `b`
-> {F | v = (|a| < |b|)} {     // Output `lt` is 1 if `a < b`, 0 otherwise

  // Iteratively calculate less-than and equality status bit-by-bit
  let (lt, _) = iter 0 (k-1) (
    \i. \(lt, eq). ( 
      #Or lt (#And eq (#LessThan a[i] b[i])),  // Update `lt` if current bit of `a` is smaller than that of `b`
      #And eq (#Eq a[i] b[i])                // Update `eq` if current bits are equal
    )
  )
  (0, 1) // Initial state: less-than is 0, equality is 1

  inv:(\i. {F | v = (|a[:i]| < |b[:i]|)} *   // Refinement type invariant for less-than
           {F | v = (|a[:i]| = |b[:i]|)})   // Refinement type invariant for equality
  in lt
}
```

1. **Refinement Types in BigLessThan**:
   - `k: {Z | 0 <= v}` ensures `k` is a non-negative integer, representing the number of bits.
   - `a: {F | binary v}^k` specifies that `a` is a binary-encoded field element of size `k`.
   - `b: {F | binary v}^k` specifies that `b` is a binary-encoded field element of size `k`.
   - The output `{F | v = (|a| < |b|)}` guarantees that the circuit's result `lt` is `1` if `a` is less than `b`, otherwise `0`.

2. **Logic of the Circuit**:
   - The `iter` function processes each bit of `a` and `b` from most significant to least significant.
   - At each iteration:
     - `lt` is updated based on whether `a[i] < b[i]`.
     - `eq` ensures that comparison continues only if the current bits are equal.
   - Refinement invariants (`inv`) ensure correctness:
     - `{F | v = (|a[:i]| < |b[:i]|)}`: the value of `lt` reflects whether the prefix of `a` up to index `i` is less than the prefix of `b` up to index `i`.
     - `{F | v = (|a[:i]| = |b[:i]|)}`: the value of `eq` reflects whether the prefix of `a` up to index `i` equals the prefix of `b` up to index `i`.

3. **Output**:
   - After processing all bits, `lt` is returned, indicating whether `a < b`.

---

## Signal Tagging
