# Contributing to PQC-VPN

We welcome contributions to PQC-VPN! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:
- Be respectful and inclusive
- Focus on constructive collaboration
- Respect different viewpoints and experiences
- Accept responsibility for mistakes and learn from them

## How to Contribute

### Reporting Issues

1. Check existing issues to avoid duplicates
2. Use the issue template
3. Provide detailed information:
   - Environment details (OS, version, configuration)
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs or error messages

### Suggesting Features

1. Open a feature request issue
2. Describe the use case and benefits
3. Provide implementation suggestions if possible
4. Consider backwards compatibility

### Code Contributions

#### Development Setup

```bash
# Clone the repository
git clone https://github.com/QEntangle/PQC-VPN.git
cd PQC-VPN

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

#### Coding Standards

**Python Code:**
- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Write docstrings for functions and classes
- Maximum line length: 88 characters (Black default)

**Shell Scripts:**
- Use shellcheck for validation
- Include error handling
- Add comments for complex logic
- Use meaningful variable names

**Configuration Files:**
- Use consistent indentation
- Include comments explaining complex configurations
- Validate syntax before committing

#### Code Quality Tools

```bash
# Format code
black tools/ scripts/

# Lint code
flake8 tools/ scripts/
mypy tools/

# Security scanning
bandit -r tools/
safety check

# Shell script validation
shellcheck scripts/*.sh
```

#### Testing

```bash
# Run unit tests
pytest tests/unit/

# Run integration tests
pytest tests/integration/

# Run all tests with coverage
pytest --cov=tools --cov-report=html

# Performance tests
python3 tools/performance-test.py
```

#### Pull Request Process

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
   - Follow coding standards
   - Add tests for new functionality
   - Update documentation as needed
4. **Test your changes**
   ```bash
   # Run all tests
   pytest
   
   # Verify formatting
   black --check .
   
   # Run linting
   flake8
   ```
5. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add new feature description"
   ```
6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Create a Pull Request**
   - Use descriptive title and description
   - Reference related issues
   - Include testing evidence
   - Update documentation if needed

#### Commit Message Guidelines

Use conventional commits format:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(auth): add multi-factor authentication support
fix(crypto): resolve Kyber key generation issue
docs: update installation guide for Windows
test(vpn): add integration tests for connection handling
```

### Documentation Contributions

#### Documentation Standards
- Use Markdown format
- Include code examples where appropriate
- Test all commands and procedures
- Use consistent terminology
- Include screenshots for UI components

#### Documentation Structure
```
docs/
├── installation.md
├── configuration.md
├── api-reference.md
├── troubleshooting.md
├── security.md
└── images/
    └── screenshots/
```

### Security Contributions

#### Reporting Security Issues

**DO NOT** create public issues for security vulnerabilities.

Instead:
1. Email security@qentangle.com
2. Include detailed vulnerability information
3. Provide proof of concept if possible
4. Allow time for responsible disclosure

#### Security Review Process

1. Security team reviews the report
2. Vulnerability is confirmed and assessed
3. Fix is developed and tested
4. Security advisory is prepared
5. Fix is released
6. Public disclosure (if appropriate)

### Release Process

#### Version Numbering

We use Semantic Versioning (SemVer):
- `MAJOR.MINOR.PATCH`
- Major: Breaking changes
- Minor: New features (backwards compatible)
- Patch: Bug fixes (backwards compatible)

#### Release Checklist

1. **Pre-release Testing**
   - [ ] All tests pass
   - [ ] Security scan clean
   - [ ] Performance benchmarks acceptable
   - [ ] Documentation updated

2. **Release Preparation**
   - [ ] Update version numbers
   - [ ] Update CHANGELOG.md
   - [ ] Tag release
   - [ ] Build and test packages

3. **Release Deployment**
   - [ ] Deploy to staging
   - [ ] Validate staging deployment
   - [ ] Deploy to production
   - [ ] Announce release

### Community Guidelines

#### Getting Help

- **Documentation**: Check existing documentation first
- **Issues**: Search existing issues before creating new ones
- **Discussions**: Use GitHub Discussions for questions
- **Support**: Contact support@qentangle.com for urgent issues

#### Communication Channels

- **GitHub Issues**: Bug reports, feature requests
- **GitHub Discussions**: General questions, ideas
- **Email**: security@qentangle.com for security issues
- **Community Forum**: https://community.qentangle.com

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation
- Annual contributor appreciation

## License

By contributing to PQC-VPN, you agree that your contributions will be licensed under the same MIT License that covers the project.

## Questions?

If you have questions about contributing, please:
1. Check this document
2. Search existing issues and discussions
3. Ask in GitHub Discussions
4. Contact the maintainers

Thank you for contributing to PQC-VPN!
