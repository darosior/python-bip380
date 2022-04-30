# Copyright (c) 2020 The Bitcoin Core developers
# Copyright (c) 2021 Antoine Poinsot
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .errors import MiniscriptPropertyError


# TODO: implement __eq__
class Property:
    """Miniscript expression property"""

    # "B": Base type
    # "V": Verify type
    # "K": Key type
    # "W": Wrapped type
    # "z": Zero-arg property
    # "o": One-arg property
    # "n": Nonzero arg property
    # "d": Dissatisfiable property
    # "u": Unit property
    # "e": Expression property
    # "f": Forced property
    # "s": Safe property
    # "m": Nonmalleable property
    types = "BVKW"
    props = "zonduefsm"

    def __init__(self, property_str=""):
        """Create a property, optionally from a str of property and types"""
        for c in property_str:
            if c not in self.types + self.props:
                raise MiniscriptPropertyError(f"Invalid property/type character '{c}'")

        for literal in self.types + self.props:
            setattr(self, literal, literal in property_str)

    def __repr__(self):
        """Generate string representation of property"""
        return "".join([c for c in self.types + self.props if getattr(self, c)])

    def has_all(self, properties):
        """Given a str of types and properties, return whether we have all of them"""
        return all([getattr(self, pt) for pt in properties])

    def has_any(self, properties):
        """Given a str of types and properties, return whether we have at least one of them"""
        return any([getattr(self, pt) for pt in properties])

    def check_valid(self):
        """Raises a MiniscriptPropertyError if the types/properties conflict"""
        # Can only be of a single type.
        num_types = 0
        for typ in self.types:
            if getattr(self, typ):
                if num_types == 1:
                    raise MiniscriptPropertyError(
                        "A Miniscript fragment can only be of a single type"
                    )
                num_types += 1

        # Check for conflicts in type & properties.
        checks = [
            # (type/property, must_be, must_not_be)
            ("K", "us", ""),
            ("V", "f", "due"),
            ("z", "m", "o"),
            ("n", "", "z"),
            ("e", "d", "f"),
            ("d", "", "f"),
        ]
        conflicts = []

        for (attr, must_be, must_not_be) in checks:
            if not getattr(self, attr):
                continue
            if not self.has_all(must_be):
                conflicts.append(f"{attr} must be {must_be}")
            if self.has_any(must_not_be):
                conflicts.append(f"{attr} must not be {must_not_be}")
        if conflicts:
            raise MiniscriptPropertyError(f"Conflicting types and properties: {', '.join(conflicts)}")

    def type(self):
        return "".join(filter(lambda x: x in self.types, str(self)))

    def properties(self):
        return "".join(filter(lambda x: x in self.props, str(self)))
