# Contributing

Thank you for your interest in contributing to the AlertLogic MCP Server!

## How to Contribute

### Reporting Bugs

Before opening a new issue, please search existing issues to avoid duplicates. When reporting a bug, include:

- A clear description of the problem
- Steps to reproduce the behavior
- Expected vs. actual behavior
- Your environment (OS, Python version, MCP client)
- Relevant logs or error messages (redact any credentials or sensitive data)

### Suggesting Features

Open a GitHub issue with the label `enhancement`. Describe the use case and why the feature would be valuable to the broader community.

### Submitting Code Changes

1. **Fork** the repository and clone your fork locally.
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**, following the existing code style and conventions.
4. **Add or update tests** if applicable.
5. **Ensure the project runs** without errors:
   ```bash
   pip install -r requirements.txt
   python main.py
   ```
6. **Commit your changes** with a clear, descriptive commit message.
7. **Push** your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
8. **Open a Pull Request** against the `main` branch of this repository.

### Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR.
- Describe what the PR does and why in the PR description.
- Link any related issues using GitHub keywords (e.g., `Closes #123`).
- Be responsive to review feedback.

## Code Style

- Follow the existing Python conventions in the codebase.
- Use meaningful variable and function names.
- Keep functions small and focused on a single responsibility.
- Follow PEP 8 guidelines where applicable.

## Security

If you discover a security vulnerability, please do **not** open a public issue. Follow the process described in [SUPPORT.md](SUPPORT.md).

## License

By contributing, you agree that your contributions will be licensed under the same license as this project. See [LICENSE](LICENSE) for details.
