from setuptools import find_packages, setup

setup(
    name="hns-taproot",
    version="0.2.0",
    description="Taproot-style (BIP340/341 pattern) key- and script-path spending for Handshake (HNS) name outputs, with a TOTP-gated MAST recovery leaf",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="NIHON",
    url="https://learnhns.com",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.10",
    install_requires=[],
    extras_require={"dev": ["pytest>=7.0"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security :: Cryptography",
        "Development Status :: 3 - Alpha",
    ],
)
