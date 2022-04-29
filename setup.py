from setuptools import find_packages, setup
import bip380
import io


with io.open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with io.open("requirements.txt", encoding="utf-8") as f:
    requirements = [r for r in f.read().split('\n') if len(r)]

setup(name="bip380",
      version=bip380.__version__,
      description="Bitcoin Output Script Descriptors (with Miniscript)",
      long_description=long_description,
      long_description_content_type="text/markdown",
      url="http://github.com/darosior/python-bip380",
      author="Antoine Poinsot",
      author_email="darosior@protonmail.com",
      license="MIT",
      packages=find_packages(),
      keywords=["bitcoin", "miniscript", "script", "descriptor"],
      install_requires=requirements)
