import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="reflex-core",
    version="0.0.1",
    author="Cloud Mitigator",
    author_email="cloudmitigator@gmail.com",
    description="Package for providing core Reflex rule classes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pangolock/reflex-core",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MPL2 License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
)
