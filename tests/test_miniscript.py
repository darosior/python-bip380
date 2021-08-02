import pytest

from miniscript.miniscript import Node

def test_simple_sanity_checks():
    not_aliased = Node.from_desc("and_v(vc:pk_k(027a1b8c69c6a4e90ce85e0dd6fb99c51ef8af35b88f20f9f74f8f937f7acaec15),c:pk_k(023c110f0946ed6160ee95eee86efb79d13421d1b460f592b04dd21d74852d7631))")
    aliased = Node.from_desc("and_v(v:pk(027a1b8c69c6a4e90ce85e0dd6fb99c51ef8af35b88f20f9f74f8f937f7acaec15),pk(023c110f0946ed6160ee95eee86efb79d13421d1b460f592b04dd21d74852d7631))")
    assert aliased.script == not_aliased.script
