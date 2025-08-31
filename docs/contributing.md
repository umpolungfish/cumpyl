# Contributing

We welcome contributions to Cumpyl! Please see our [CONTRIBUTING.md](../CONTRIBUTING.md) file for details on how to contribute to the project.

## Getting Started

1. Fork the repository
2. Create a new branch for your feature or bug fix
3. Make your changes
4. Write tests for your changes
5. Ensure all tests pass
6. Submit a pull request

## Code of Conduct

Please note that this project is released with a [Code of Conduct](../CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

## Development Setup

To set up a development environment:

```bash
git clone https://github.com/umpolungfish/cumpyl.git
cd cumpyl
pip install -e ".[dev,test]"
```

## Running Tests

To run the test suite:

```bash
pytest tests/
```

## Code Style

We use `black` for code formatting and `ruff` for linting. Please ensure your code passes both before submitting a PR.