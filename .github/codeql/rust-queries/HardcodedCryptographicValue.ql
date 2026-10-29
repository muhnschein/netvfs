// SPDX-License-Identifier: MIT
// Copy of github/codeql rust/ql/src/queries/security/CWE-798/HardcodedCryptographicValue.ql
// (codeql/rust-queries 0.1.45, Copyright (c) GitHub, Inc., MIT), plus barrier
// `usesFilledBuffer`.
/**
 * @name Hard-coded cryptographic value
 * @description Using hard-coded keys, passwords, salts or initialization
 *              vectors is not secure.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 9.8
 * @precision high
 * @id rust/hard-coded-cryptographic-value
 * @tags security
 *       external/cwe/cwe-259
 *       external/cwe/cwe-321
 *       external/cwe/cwe-798
 *       external/cwe/cwe-1204
 */

import rust
import codeql.rust.security.HardcodedCryptographicValueExtensions
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.TaintTracking
import codeql.rust.dataflow.internal.DataFlowImpl
import codeql.rust.dataflow.internal.Content

/** Holds if local `v` starts as zeros: `let v = [0u8; N]`. */
predicate zeroedBuffer(Variable v) {
  v.getInitializer()
      .(ArrayRepeatExpr)
      .getRepeatOperand()
      .(IntegerLiteralExpr)
      .getTextValue()
      .regexpMatch("0+(_?[iu][0-9a-z]+)?")
}

/** Holds if `e` lends `v` out mutably: `&mut v`, or `v.m(..)` with `&mut self`. */
predicate lendsMutably(Variable v, Expr e) {
  e = v.getAnAccess() and
  (
    exists(RefExpr r | r.isMut() and r.getExpr() = e)
    or
    exists(MethodCallExpr c, SelfParam s |
      c.getReceiver() = e and
      s = c.getStaticTarget().getSelfParam() and
      s.isRef() and
      s.isMut()
    )
  )
}

/**
 * Holds if `e` uses zeroed buffer `v` at or after a place that lends `v` out
 * mutably, in source order. Zeros are placeholder there; lender fills buffer
 * (random bytes, counter and salt). Stock query knows only direct
 * `getrandom::fill`. Still reported: non-zero initializers, uses before first
 * lend, buffers never lent mutably.
 */
predicate usesFilledBuffer(Expr e) {
  exists(Variable v, Expr lend, Location l, Location u |
    zeroedBuffer(v) and
    lendsMutably(v, lend) and
    e = v.getAnAccess() and
    l = lend.getLocation() and
    u = e.getLocation()
  |
    l.getStartLine() < u.getStartLine()
    or
    l.getStartLine() = u.getStartLine() and l.getStartColumn() <= u.getStartColumn()
  )
}

/**
 * A taint-tracking configuration for hard-coded cryptographic value vulnerabilities.
 */
module HardcodedCryptographicValueConfig implements DataFlow::ConfigSig {
  import HardcodedCryptographicValue

  predicate isSource(DataFlow::Node source) { source instanceof Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink }

  predicate isBarrier(DataFlow::Node barrier) {
    barrier instanceof Barrier or usesFilledBuffer(barrier.asExpr())
  }

  predicate isBarrierIn(DataFlow::Node node) {
    // make sources barriers so that we only report the closest instance
    // (this combined with sources for `ArrayListExpr` means we only get one source in
    //  case like `[0, 0, 0, 0]`)
    isSource(node)
  }

  predicate isBarrierOut(DataFlow::Node node) {
    // make sinks barriers so that we only report the closest instance
    isSink(node)
  }
}

module HardcodedCryptographicValueFlow = TaintTracking::Global<HardcodedCryptographicValueConfig>;

import HardcodedCryptographicValueFlow::PathGraph

from
  HardcodedCryptographicValueFlow::PathNode source, HardcodedCryptographicValueFlow::PathNode sink
where HardcodedCryptographicValueFlow::flowPath(source, sink)
select source.getNode(), source, sink, "This hard-coded value is used as $@.", sink,
  sink.getNode().(HardcodedCryptographicValueConfig::Sink).getKind().getDescription()
