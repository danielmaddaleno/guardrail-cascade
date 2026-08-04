"""Tests for the core abstractions."""

import pytest

from guardrail_cascade.core import Action, CheckResult, Guardrail


def test_action_severity_is_ordered():
    assert Action.ALLOW < Action.FLAG < Action.REDACT < Action.BLOCK
    assert max(Action.FLAG, Action.BLOCK, Action.ALLOW) is Action.BLOCK


def test_check_result_defaults():
    result = CheckResult(guardrail="X", action=Action.ALLOW)
    assert result.reason == ""
    assert result.output is None
    assert result.detail == {}


def test_check_result_is_frozen():
    result = CheckResult(guardrail="X", action=Action.ALLOW)
    with pytest.raises(Exception):
        result.action = Action.BLOCK


def test_guardrail_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        Guardrail()


def test_guardrail_name_defaults_to_class_name():
    class MyGuard(Guardrail):
        def check(self, text: str) -> CheckResult:
            return CheckResult(guardrail=self.name, action=Action.ALLOW)

    assert MyGuard().name == "MyGuard"
