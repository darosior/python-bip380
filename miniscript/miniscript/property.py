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
        if not (
            (not self.z or not self.o)
            and (not self.n or not self.z)
            and (not self.V or not self.d)
            and (not self.K or self.u)
            and (not self.V or not self.u)
            and (not self.e or not self.f)
            and (not self.e or self.d)
            and (not self.V or not self.e)
            and (not self.d or not self.f)
            and (not self.V or self.f)
            and (not self.K or self.s)
            and (not self.z or self.m)
        ):
            raise MiniscriptPropertyError("Conflicting types and properties")

    def type(self):
        return "".join(filter(lambda x: x in self.types, str(self)))

    def properties(self):
        return "".join(filter(lambda x: x in self.props, str(self)))
