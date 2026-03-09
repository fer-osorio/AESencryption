# Angular Commit Convention Quick Reference

## Format:
```
<type>(<scope>): <subject>

<body>

<footer>
```

## Common Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code formatting (whitespace, indentation, etc.)
- `refactor`: Code restructuring without changing behavior
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks (dependencies, build config)
- `ci`: CI/CD configuration changes
- `build`: Build system changes
- `revert`: Revert a previous commit

## Rules
- Subject: imperative mood, lowercase, no period, ≤50 chars
- Body: optional, explain what and why (not how)
- Footer: optional, reference issues (e.g., "Closes #123")
- Breaking changes: add `BREAKING CHANGE:` in footer or `!` after type/scope
