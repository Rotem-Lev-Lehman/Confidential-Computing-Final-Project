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

MODULAR RECONSTRUCTION
----------------------
The secure-summation layer hands over shares from a finite field 𝔽ₚ, so ``A``
and ``B`` reconstruct the true count only *modulo p*: as integers,
``A + B`` is either ``T`` or ``T + p``.  Passing ``modulus=p`` inserts a
conditional subtraction (``S ≥ p ? S − p : S``) between the adder and the
comparator, so the circuit decides ``T > threshold`` exactly.  This is what lets
Phase 1's additive secret sharing feed Phase 3 directly, with the
information-theoretic hiding of the field intact — no statistical masking
needed.  ``modulus=None`` keeps the plain, non-modular behaviour used by the
mocked problems in ``problems/``.
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
    bit_length: int,
    threshold: int,
    region_id: int,
    clear_token: int,
    modulus: int | None = None,
) -> Circuit:
    """Build ``(A + B > threshold) ? region_id : clear_token`` for one region.

    ``A`` is the garbler's private ``bit_length``-bit share, ``B`` the
    evaluator's.  Structure: a ripple-carry adder for ``A + B``, an optional
    conditional subtraction of ``modulus``, a comparison against the public
    ``threshold``, then a bit-wise multiplexer choosing between the public
    ``region_id`` and ``clear_token`` constants.

    Args:
        bit_length: width of each party's share.
        threshold: public quarantine threshold; a region crosses when the
            reconstructed count is strictly greater.
        region_id: public, non-zero id revealed when the threshold is crossed.
        clear_token: public sentinel revealed otherwise.
        modulus: if given, ``A`` and ``B`` are shares over 𝔽_modulus and the
            circuit reduces ``A + B`` mod ``modulus`` before comparing.  Must be
            at most ``2**bit_length`` so both shares fit their wires.
    """
    if modulus is not None and not 2 <= modulus <= (1 << bit_length):
        raise ValueError(
            f"modulus {modulus} must be in [2, 2**bit_length] "
            f"(bit_length={bit_length})"
        )

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

    # --- reduce mod `modulus`, if the shares live in a finite field ---
    #
    # Both shares are < modulus, so the integer sum is < 2*modulus and a single
    # conditional subtraction suffices:  S >= modulus  ?  S - modulus  :  S.
    if modulus is not None:
        over = _greater_than_const(nl, total, modulus - 1)  # 1 iff S >= modulus
        reduced = _add_const(nl, total, (1 << len(total)) - modulus)  # S - modulus
        total = _mux(nl, over, reduced, total)

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


def _add_const(nl: _Netlist, x_bits: list[int], constant: int) -> list[int]:
    """Add a public ``constant`` to the secret number ``x_bits``, same width.

    The final carry is discarded, so this is addition modulo ``2**len(x_bits)``
    — which is exactly what makes it a *subtraction*: adding the two's
    complement ``2**k - m`` computes ``x - m`` whenever ``x >= m``.

    Because the constant's bits are public, each position needs at most one AND
    gate (``carry AND x`` or ``carry OR x``) instead of a full adder's three.
    """
    out: list[int] = []
    carry: int | None = None
    for i, x in enumerate(x_bits):
        c_i = (constant >> i) & 1
        if carry is None:  # first position: no incoming carry
            out.append(nl.not_(x) if c_i else x)
            carry = x if c_i else nl.zero()
            continue
        total_bit = nl.xor(x, carry)
        # sum = x XOR carry XOR c_i ; carry_out = majority(x, carry, c_i)
        if c_i:
            out.append(nl.not_(total_bit))
            carry = nl.or_(x, carry)
        else:
            out.append(total_bit)
            carry = nl.and_(x, carry)
    return out


def _mux(nl: _Netlist, sel: int, on_true: list[int], on_false: list[int]) -> list[int]:
    """Bit-wise ``sel ? on_true : on_false`` — one AND gate per bit."""
    return [
        nl.xor(f, nl.and_(sel, nl.xor(t, f))) for t, f in zip(on_true, on_false)
    ]


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
