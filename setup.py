from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cumpyl",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A binary rewriting tool with encoding/decoding capabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/cumpyl",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
    ],
    python_requires=">=3.9",
    install_requires=[
        "lief",
        "capstone",
        "keystone-engine",
        "rich",
        "tqdm",
    ],
    entry_points={
        "console_scripts": [
            "cumpyl=cumpyl_package.cumpyl:main",
        ],
    },
)