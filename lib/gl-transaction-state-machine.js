// gl-transaction-state-machine.js
//
// Pure mirror of the transition graph enforced by
// transition_gl_transaction_status() in
// 023_gl_ledger_phase1_reconciliation.sql. Same relationship as
// card-funding-state-machine.js has to its own SQL function: this is
// NOT the source of truth, it's a pre-flight check so an obviously
// illegal transition is rejected with a clear error before ever
// reaching the database. If you change the transition graph, change
// it in both places.

const ALL_STATUSES = [
  "INITIATED", "PENDING", "AUTHORIZED", "POSTED", "SETTLED", "FAILED", "REVERSED", "CORRECTED",
];

const TRANSITIONS = {
  INITIATED: ["PENDING", "AUTHORIZED", "FAILED"],
  PENDING: ["AUTHORIZED", "POSTED", "FAILED"],
  AUTHORIZED: ["POSTED", "FAILED"],
  POSTED: ["SETTLED", "REVERSED"],
  SETTLED: ["REVERSED", "CORRECTED"],
  FAILED: [],       // terminal
  REVERSED: [],      // terminal
  CORRECTED: ["REVERSED"],
};

function canTransition(from, to) {
  if (!ALL_STATUSES.includes(from) || !ALL_STATUSES.includes(to)) return false;
  return (TRANSITIONS[from] || []).includes(to);
}

function assertTransition(from, to) {
  if (!canTransition(from, to)) {
    const err = new Error(`Illegal gl_transaction transition: ${from} -> ${to}`);
    err.code = "ILLEGAL_TRANSITION";
    throw err;
  }
}

module.exports = { ALL_STATUSES, TRANSITIONS, canTransition, assertTransition };