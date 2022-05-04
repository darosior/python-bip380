"""
All the exceptions raised when dealing with Miniscript.
"""


class MiniscriptNodeCreationError(ValueError):
    def __init__(self, message: str):
        self.message: str = message


class MiniscriptPropertyError(ValueError):
    def __init__(self, message: str):
        self.message: str = message

# TODO: errors for type errors, parsing errors, etc..
