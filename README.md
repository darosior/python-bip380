# Bitcoin Script Descriptors, with Miniscript extension

## About

In Bitcoin, output [Script](https://en.bitcoin.it/wiki/Script)s are used to express the conditions
by which the amount associated with the output may be spent.

**Output Script Descriptors** are a simple language which can be used to describe such Scripts
generally and precisely.  Bitcoin Output Script Descriptors are defined in a set of
[BIP](https://github.com/bitcoin/bips/blob/master/bip-0001.mediawiki)s, the main one being
[bip-0380](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki).

**Miniscript** is a language for writing (a subset of) Bitcoin Scripts in a structured way. It is an
extension to Output Script Descriptors and is currently only defined within P2WSH context.

Miniscript permits:
- To safely extend the Output Descriptor language to many more scripting features thanks to the
  typing system (composition).
- Statical analysis of spending conditions, maximum spending cost of each branch, security
  properties, third-party malleability.
- General satisfaction of any correctly typed ("valid") Miniscript. The satisfaction itself is
  also analyzable.
- To extend the possibilities of external signers, because of all of the above and since it carries
  enough metadata.

Miniscript guarantees:
- That for any statically-analyzed as "safe" Script, a witness can be constructed in the bounds of
  the consensus and standardness rules (standardness complete).
- That unless the conditions of the Miniscript are met, no witness can be created for the Script
  (consensus sound).
- Third-party malleability protection for the satisfaction of a sane Miniscript, which is too
  complex to summarize here.

This library provides an implementation of Segwit-native Output Descriptors and of Miniscript (to be
used within `wsh()` descriptors), with a minimal amount of dependencies.


## WIP: this is not ready for any real use!

This library is still a work in progress. It contains known bugs (in the satisfier for instance) and
there are probably many unknown ones.

Still, it's ready for hacking around and contributions are welcome. See the [issue
tracker](https://github.com/darosior/python-miniscript/issues) for ideas on where to start.
