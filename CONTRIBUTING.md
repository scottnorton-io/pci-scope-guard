# Contributing to PCI Scope Guard

Thank you for your interest in contributing!

## Development Setup

1. Fork the repository
2. Clone your fork: `git clone 124`
3. Create a branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Run tests: `make test`
6. Run linters: `make lint`
7. Commit: `git commit -m "Add feature"`
8. Push: `git push origin feature/your-feature`
9. Open a Pull Request

## Code Standards

- Python 3.11+
- Type hints required
- Black formatting
- Docstrings for all public functions
- Tests for new features
- Update documentation

## Testing
```bash
# Run all tests

make test

# Run specific test

pytest tests/unit/test_[classifier.py](http://classifier.py) -v

# Coverage report

pytest --cov=src --cov-report=html
```

## Pull Request Guidelines

- One feature per PR
- Update README if needed
- Add tests for new code
- Ensure CI passes
- Reference issue numbers
