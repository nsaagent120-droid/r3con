from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="r3con",
    version="5.0.0",
    author="r3con contributors",
    description="Advanced Binary, APK & Firmware Security Research Tool — AI-assisted",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "click>=8.1.0",
        "rich>=13.0.0",
    ],
    extras_require={
        "ai":       ["anthropic>=0.20.0"],
        "binary":   ["capstone>=5.0.0", "lief>=0.13.0"],
        "full":     ["anthropic>=0.20.0", "openai>=1.3.0", "together>=0.2.0", "yara-python>=4.5.0", "capstone>=5.0.0",
                     "lief>=0.13.0", "pyyaml>=6.0", "jinja2>=3.1.0", "tree-sitter>=0.21.0",
                     "tree-sitter-c>=0.21.0", "z3-solver>=4.12.0"],
    },
    entry_points={
        "console_scripts": [
            "r3con=cli.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
    ],
)
