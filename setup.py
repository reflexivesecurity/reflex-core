import setuptools
import os

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="reflex-core",
    version=f"{os.environ['VERSION']}",
    author="Reflexive Security",
    author_email="info@reflexivesecurity.com",
    description="Package for providing core Reflex rule classes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pangolock/reflex-core",
    packages=setuptools.find_packages(),
    install_requires=["boto3"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
)
