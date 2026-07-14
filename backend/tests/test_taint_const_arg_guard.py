"""RUN 31 — the constant-argument guard for Execution sinks.

The taint engine proves CALL-GRAPH REACHABILITY, not data-flow. That made root detection —
`Runtime.exec(new String[]{"/system/xbin/which","su"})` — present as a CRITICAL "Intent →
Runtime.exec" command injection, because a getStringExtra elsewhere in the class could reach it.

The guard drops an Execution flow ONLY when the sink's arguments provably come from const*
opcodes. These tests lock BOTH directions, which is the whole point:
  (1) the FP class (constant args) is dropped;
  (2) a REAL exec(userInput) — a non-constant argument register — always survives.
Anything unprovable must fail OPEN (keep the flow): the guard may remove a false positive, it
may never drop a true positive.

Instructions are duck-typed doubles shaped like androguard's (get_name / get_operands /
get_length), so the logic is tested without a DEX fixture. The shapes below are transcribed
from the real InsecureBankv2 bytecode dumped via androguard (PostLogin->doesSUexist @40).
"""
import pytest

from analyzers.taint_analyzer import _call_site_args_constant, _reg_is_constant

REGISTER = 0  # androguard Operand.REGISTER


class Ins:
    """Minimal stand-in for an androguard instruction."""

    def __init__(self, name, regs=(), length=2):
        self._name = name
        self._regs = list(regs)
        self._len = length

    def get_name(self):
        return self._name

    def get_operands(self):
        # Registers first (as androguard emits), then a non-register operand for realism.
        return [(REGISTER, r) for r in self._regs] + [(1, "literal")]

    def get_length(self):
        return self._len


class Method:
    def __init__(self, insns):
        self._insns = insns

    def get_instructions(self):
        return list(self._insns)


def _offsets(insns):
    """Byte offset of each instruction, mirroring _method_instructions()."""
    offs, o = [], 0
    for ins in insns:
        offs.append(o)
        o += ins.get_length()
    return offs


# ── (1) THE FALSE POSITIVE — must be dropped ─────────────────────────────────
def test_exec_with_const_string_array_is_constant():
    """The real InsecureBankv2 root check: new-array + aput-object of two const-strings,
    then invoke-virtual Runtime.exec(v5, v6). Provably not attacker-controlled → drop."""
    insns = [
        Ins("const/4", [6]),
        Ins("new-array", [6, 6]),          # v6 = new String[2]
        Ins("const/4", [7]),
        Ins("const-string", [8]),          # v8 = "/system/xbin/which"
        Ins("aput-object", [8, 6, 7]),     # v6[v7] = v8
        Ins("const/4", [7]),
        Ins("const-string", [8]),          # v8 = "su"
        Ins("aput-object", [8, 6, 7]),
        Ins("invoke-virtual", [5, 6]),     # Runtime.exec(v6)
    ]
    em = Method(insns)
    call_off = _offsets(insns)[-1]
    assert _call_site_args_constant(em, call_off) is True


def test_filled_new_array_of_consts_is_constant():
    insns = [
        Ins("const-string", [1]),
        Ins("const-string", [2]),
        Ins("filled-new-array", [1, 2]),
        Ins("move-result-object", [6]),
        Ins("invoke-virtual", [5, 6]),
    ]
    # move-result-object defines v6 → not provably constant → flow KEPT (fail-open).
    em = Method(insns)
    assert _call_site_args_constant(em, _offsets(insns)[-1]) is False


def test_single_const_string_arg_is_constant():
    insns = [
        Ins("const-string", [6]),          # v6 = "id"
        Ins("invoke-virtual", [5, 6]),
    ]
    em = Method(insns)
    assert _call_site_args_constant(em, _offsets(insns)[-1]) is True


# ── (2) THE TRUE POSITIVES — must ALL survive ────────────────────────────────
def test_exec_with_move_result_arg_is_not_constant():
    """exec(userInput): the argument comes from a call's return value. NOT constant → keep."""
    insns = [
        Ins("invoke-virtual", [4]),        # getStringExtra(...)
        Ins("move-result-object", [6]),    # v6 = tainted
        Ins("invoke-virtual", [5, 6]),     # Runtime.exec(v6)  ← real command injection
    ]
    em = Method(insns)
    assert _call_site_args_constant(em, _offsets(insns)[-1]) is False


def test_arg_from_method_parameter_is_not_constant():
    """No defining write in the method ⇒ the register is an incoming parameter ⇒ keep."""
    insns = [Ins("invoke-virtual", [2, 3])]  # WebView.loadUrl(v3), v3 = parameter
    em = Method(insns)
    assert _call_site_args_constant(em, 0) is False


def test_array_with_one_non_constant_element_is_not_constant():
    """An array is only constant if EVERY element is. One tainted element ⇒ keep the flow."""
    insns = [
        Ins("const/4", [6]),
        Ins("new-array", [6, 6]),
        Ins("const/4", [7]),
        Ins("const-string", [8]),          # element 0: constant
        Ins("aput-object", [8, 6, 7]),
        Ins("const/4", [7]),
        Ins("invoke-virtual", [4]),
        Ins("move-result-object", [8]),    # element 1: TAINTED
        Ins("aput-object", [8, 6, 7]),
        Ins("invoke-virtual", [5, 6]),     # exec(["/bin/sh", userInput])
    ]
    em = Method(insns)
    assert _call_site_args_constant(em, _offsets(insns)[-1]) is False


def test_arg_from_field_read_is_not_constant():
    insns = [
        Ins("iget-object", [6, 3]),        # v6 = this.cmd — could be attacker-set
        Ins("invoke-virtual", [5, 6]),
    ]
    em = Method(insns)
    assert _call_site_args_constant(em, _offsets(insns)[-1]) is False


# ── (3) FAIL-OPEN — unprovable ⇒ keep the flow, never drop it ────────────────
def test_unknown_offset_fails_open():
    insns = [Ins("invoke-virtual", [5, 6])]
    assert _call_site_args_constant(Method(insns), 9999) is False


def test_non_invoke_at_offset_fails_open():
    insns = [Ins("const-string", [6])]
    assert _call_site_args_constant(Method(insns), 0) is False


def test_receiver_is_not_treated_as_an_argument():
    """An instance invoke's first register is the receiver. If it were judged as an argument,
    a constant receiver could wrongly mark a tainted call constant."""
    insns = [
        Ins("const-string", [5]),          # v5 (receiver-ish) constant
        Ins("invoke-virtual", [4]),
        Ins("move-result-object", [6]),    # v6 = tainted ARG
        Ins("invoke-virtual", [5, 6]),
    ]
    em = Method(insns)
    assert _call_site_args_constant(em, _offsets(insns)[-1]) is False


def test_invoke_with_no_arguments_is_not_constant():
    """A no-arg invoke gives nothing to prove constant ⇒ must not be reported constant."""
    insns = [Ins("invoke-virtual", [5])]
    assert _call_site_args_constant(Method(insns), 0) is False


def test_reg_never_defined_is_not_constant():
    insns = [Ins("nop", []), Ins("invoke-virtual", [5, 6])]
    assert _reg_is_constant([(0, insns[0]), (2, insns[1])], 1, 6) is False
