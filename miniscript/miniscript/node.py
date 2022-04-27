from .parsing import miniscript_from_script, miniscript_from_str
from .script import CScript


class Node:
    """A Miniscript fragment."""

    # The fragment's type and properties
    p = None
    # List of all sub fragments
    subs = []
    # A list of Script elements, a CScript is created all at once in the script() method.
    _script = []
    # Whether any satisfaction for this fragment require a signature
    needs_sig = None
    # Whether any dissatisfaction for this fragment requires a signature
    is_forced = None
    # Whether this fragment has a unique unconditional satisfaction, and all conditional
    # ones require a signature.
    is_expressive = None
    # Whether for any possible way to satisfy this fragment (may be none), a
    # non-malleable satisfaction exists.
    is_nonmalleable = None
    # Whether this node or any of its subs contains an absolute heightlock
    abs_heightlocks = None
    # Whether this node or any of its subs contains a relative heightlock
    rel_heightlocks = None
    # Whether this node or any of its subs contains an absolute timelock
    abs_timelocks = None
    # Whether this node or any of its subs contains a relative timelock
    rel_timelocks = None
    # Whether this node does not contain a mix of timelock or heightlock of different types.
    # That is, not (abs_heightlocks and rel_heightlocks or abs_timelocks and abs_timelocks)
    no_timelock_mix = None
    # Information about this Miniscript execution (satisfaction cost, etc..)
    exec_info = None

    def __init__(self, *args, **kwargs):
        # Needs to be implemented by derived classes.
        raise NotImplementedError

    def from_str(ms_str):
        """Parse a Miniscript fragment from its string representation."""
        assert isinstance(ms_str, str)
        return miniscript_from_str(ms_str)

    def from_script(script, pkh_preimages={}):
        """Decode a Miniscript fragment from its Script representation."""
        assert isinstance(script, CScript)
        return miniscript_from_script(script, pkh_preimages)

    # TODO: have something like BuildScript from Core and get rid of the _script member.
    @property
    def script(self):
        return CScript(self._script)

    def satisfy(self, sat_material):
        """Get the witness of the smallest non-malleable satisfaction for this fragment,
        if one exists.

        :param sat_material: a SatisfactionMaterial containing available data to satisfy
                             challenges.
        """
        sat = self.satisfaction(sat_material)
        if not sat.has_sig:
            return None
        return sat.witness

    def satisfaction(self, sat_material):
        """Get the satisfaction for this fragment.

        :param sat_material: a SatisfactionMaterial containing available data to satisfy
                             challenges.
        """
        # Needs to be implemented by derived classes.
        raise NotImplementedError

    def dissatisfaction(self):
        """Get the dissatisfaction for this fragment."""
        # Needs to be implemented by derived classes.
        raise NotImplementedError
