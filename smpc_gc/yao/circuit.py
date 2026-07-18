"""The one boolean circuit this project needs: ``(A + B > threshold)``.

Yao's protocol garbles a boolean circuit, so we do need the threshold check as a
gate netlist — but only *this* circuit, not a general-purpose compiler.  The
netlist is emitted directly by :func:`build_threshold_circuit` using two
primitive gate types:

    * ``XOR`` — free under the free-XOR optimization (no garbled table);
    * ``AND`` — the only gate that needs a garbled table.

``NOT a`` is just ``a XOR 1`` (a hard-wired constant-1 wire) and
``a OR b`` is ``a XOR b XOR (a AND b)``, so the evaluator only ever XORs labels
it already has or decrypts an AND row — it never touches the garbler's secrets.

Bits are little-endian: index 0 is the least-significant bit.
"""

from __future__ import annotations

from dataclasses import dataclass

XOR = "XOR"
AND = "AND"


@dataclass(frozen=True)
class Gate:
    op: str  # XOR or AND
    in0: int
    in1: int
    out: int


@dataclass(frozen=True)
class Circuit:
    """A boolean circuit for one region's threshold check.

    Attributes:
        num_wires: total wire count (inputs, constants and gate outputs).
        gates: gates in topological order — one forward pass evaluates them.
        garbler_input_wires: wires carrying the garbler's private bits (A).
        evaluator_input_wires: wires carrying the evaluator's private bits (B),
            delivered by Oblivious Transfer.
        constant_wires: wire -> fixed public bit (0/1).
        output_wires: wires whose decoded bits form the result (little-endian).
    """

    num_wires: int
    gates: tuple[Gate, ...]
    garbler_input_wires: tuple[int, ...]
    evaluator_input_wires: tuple[int, ...]
    constant_wires: dict[int, int]
    output_wires: tuple[int, ...]


class _Netlist:
    """Tiny scratchpad for emitting gates while building the one circuit."""

    def __init__(self) -> None:
        self.n = 0
        self.gates: list[Gate] = []
        self.constants: dict[int, int] = {}
        self._one: int | None = None
        self._zero: int | None = None

    def wire(self) -> int:
        w = self.n
        self.n += 1
        return w

    def const(self, value: int) -> int:
        w = self.wire()
        self.constants[w] = value & 1
        return w

    def one(self) -> int:
        if self._one is None:
            self._one = self.const(1)
        return self._one

    def zero(self) -> int:
        if self._zero is None:
            self._zero = self.const(0)
        return self._zero

    def xor(self, a: int, b: int) -> int:
        w = self.wire()
        self.gates.append(Gate(XOR, a, b, w))
        return w

    def and_(self, a: int, b: int) -> int:
        w = self.wire()
        self.gates.append(Gate(AND, a, b, w))
        return w

    def not_(self, a: int) -> int:
        return self.xor(a, self.one())

    def or_(self, a: int, b: int) -> int:
        return self.xor(self.xor(a, b), self.and_(a, b))


def build_threshold_circuit(
    bit_length: int, threshold: int, region_id: int, clear_token: int
) -> Circuit:
    """Build ``(A + B > threshold) ? region_id : clear_token`` for one region.

    ``A`` is the garbler's private ``bit_length``-bit share, ``B`` the
    evaluator's.  Structure: a ripple-carry adder for ``A + B``, a comparison
    against the public ``threshold``, then a bit-wise multiplexer choosing
    between the public ``region_id`` and ``clear_token`` constants.
    """
    nl = _Netlist()
    a_bits = [nl.wire() for _ in range(bit_length)]
    b_bits = [nl.wire() for _ in range(bit_length)]
    garbler_inputs = tuple(a_bits)
    evaluator_inputs = tuple(b_bits)

    # --- A + B : ripple-carry adder -> (bit_length + 1) sum bits ---
    total: list[int] = []
    carry = nl.zero()
    for i in range(bit_length):
        a_xor_b = nl.xor(a_bits[i], b_bits[i])
        total.append(nl.xor(a_xor_b, carry))  # sum bit
        # carry_out = (a AND b) OR (carry AND (a XOR b))
        carry = nl.or_(nl.and_(a_bits[i], b_bits[i]), nl.and_(carry, a_xor_b))
    total.append(carry)  # top sum bit

    # --- total > threshold (threshold is public) ---
    crossed = _greater_than_const(nl, total, threshold)

    # --- crossed ? region_id : clear_token, bit by bit ---
    out_width = max(region_id.bit_length(), clear_token.bit_length(), 1)
    outputs = []
    for i in range(out_width):
        r = nl.const((region_id >> i) & 1)
        c = nl.const((clear_token >> i) & 1)
        # c XOR (crossed AND (r XOR c))
        outputs.append(nl.xor(c, nl.and_(crossed, nl.xor(r, c))))

    return Circuit(
        num_wires=nl.n,
        gates=tuple(nl.gates),
        garbler_input_wires=garbler_inputs,
        evaluator_input_wires=evaluator_inputs,
        constant_wires=dict(nl.constants),
        output_wires=tuple(outputs),
    )


def _greater_than_const(nl: _Netlist, x_bits: list[int], threshold: int) -> int:
    """Return a wire that is 1 iff the little-endian number X > ``threshold``.

    Scans bits most- to least-significant with two running wires: ``eq`` (all
    higher bits equal so far) and ``gt`` (already decided greater).  Because the
    threshold is public, each step is a couple of gates on the secret bit.
    """
    if threshold < 0:
        return nl.one()
    if threshold >= (1 << len(x_bits)):
        return nl.zero()

    eq = nl.one()
    gt = nl.zero()
    for i in range(len(x_bits) - 1, -1, -1):
        t_i = (threshold >> i) & 1
        x_i = x_bits[i]
        if t_i == 0:
            gt = nl.or_(gt, nl.and_(eq, x_i))  # x_i=1 while equal => greater
            eq = nl.and_(eq, nl.not_(x_i))  # stays equal only if x_i=0
        else:
            eq = nl.and_(eq, x_i)  # equal here only if x_i=1
    return gt
