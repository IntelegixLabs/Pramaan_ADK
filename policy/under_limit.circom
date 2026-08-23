pragma circom 2.0.0;

include "circomlib/comparators.circom";

// HandshakeOS - Under Limit ZKP Circuit
// Proves: amount <= limit without revealing the exact amount.
//
// Private input: amount
// Public input: limit
// Output: ok (1 if amount <= limit, else constraint fails)

template UnderLimit() {
    signal input amount;       // private
    signal input limit;        // public
    signal output ok;

    component lessThan = LessThan(32);
    lessThan.in[0] <== amount;
    lessThan.in[1] <== limit + 1;

    ok <== lessThan.out;
    ok === 1;
}

component main {public [limit]} = UnderLimit();

