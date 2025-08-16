from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cumpyl",
    version="0.3.0",
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
        "pyyaml",
    ],
    extras_require={
        "dev": [
            "numpy",  # 𐑯𐑰𐑛𐑦𐑛 𐑓𐑹 𐑧𐑯𐑑𐑮𐑩𐑐𐑦 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑐𐑤𐑳𐑜𐑦𐑯
            "pytest",  # 𐑩𐑤𐑑𐑻𐑯𐑩𐑑𐑦𐑝 𐑑𐑧𐑕𐑑 𐑮𐑳𐑯𐑼
            "pytest-cov",  # 𐑒𐑳𐑝𐑼𐑦𐑡 𐑮𐑦𐑐𐑹𐑑𐑦𐑙
            "black",  # 𐑒𐑴𐑛 𐑓𐑹𐑥𐑨𐑑𐑦𐑙
            "flake8",  # 𐑤𐑦𐑯𐑑𐑦𐑙
        ],
        "test": [
            "numpy",
        ]
    },
    test_suite="tests",
    entry_points={
        "console_scripts": [
            "cumpyl=cumpyl_package.cumpyl:main",
        ],
    },
)