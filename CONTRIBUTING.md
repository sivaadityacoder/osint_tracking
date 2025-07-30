# Contributing to OSINT Master Tool

Thank you for your interest in contributing to the OSINT Master Tool! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- Be respectful and inclusive
- Focus on constructive feedback
- Help create a welcoming environment for all contributors
- Report any unacceptable behavior to the maintainers

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the behavior
- **Expected vs actual behavior**
- **Environment details** (OS, Python version, etc.)
- **Log files or error messages**

### Suggesting Features

Feature requests are welcome! Please provide:

- **Clear description** of the feature
- **Use case** and motivation
- **Possible implementation** approach
- **Impact** on existing functionality

### Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main` for your changes
3. **Write clear commit messages**
4. **Add tests** for new functionality
5. **Update documentation** as needed
6. **Submit a pull request**

#### Pull Request Guidelines

- Keep changes focused and atomic
- Write descriptive commit messages
- Include tests for new features
- Update documentation
- Follow existing code style
- Ensure all tests pass

## Development Setup

1. Fork and clone the repository:
```bash
git clone https://github.com/yourusername/osint_master.git
cd osint_master
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install development dependencies:
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

4. Install pre-commit hooks:
```bash
pre-commit install
```

## Code Style

- Follow PEP 8 Python style guidelines
- Use meaningful variable and function names
- Add docstrings to all public functions and classes
- Keep functions focused and single-purpose
- Use type hints where appropriate

### Example Code Style

```python
async def investigate_email(email: str, session: aiohttp.ClientSession) -> dict:
    """
    Investigate an email address using multiple OSINT sources.
    
    Args:
        email: The email address to investigate
        session: Async HTTP session for API calls
        
    Returns:
        Dictionary containing investigation results
        
    Raises:
        ValueError: If email format is invalid
    """
    if not is_valid_email(email):
        raise ValueError(f"Invalid email format: {email}")
    
    # Implementation here
    return results
```

## Plugin Development

### Creating New Plugins

1. Inherit from `PluginBase`:

```python
class NewPlugin(PluginBase):
    name = "new_source"
    description = "Description of the OSINT source"
    
    async def run(self, query: str, session: aiohttp.ClientSession) -> dict:
        """
        Run the plugin investigation.
        
        Args:
            query: The target to investigate
            session: HTTP session for API calls
            
        Returns:
            Investigation results dictionary
        """
        # Your implementation
        return {"source": "new_source", "data": results}
```

2. Add to plugin loader in `main.py`
3. Write tests for the new plugin
4. Update documentation

### Plugin Guidelines

- Handle errors gracefully
- Use async/await for HTTP requests
- Return consistent data structures
- Include rate limiting if required by API
- Add comprehensive error logging
- Respect API terms of service

## Testing

### Running Tests

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=main

# Run specific test file
python -m pytest tests/test_plugins.py
```

### Writing Tests

- Write tests for all new functionality
- Use pytest framework
- Mock external API calls
- Test both success and error cases
- Aim for high code coverage

### Test Example

```python
import pytest
import aiohttp
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_email_plugin_success():
    plugin = EmailPlugin()
    session = AsyncMock(spec=aiohttp.ClientSession)
    
    with patch('aiohttp.ClientSession.get') as mock_get:
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value=[{"Name": "TestBreach"}])
        mock_get.return_value.__aenter__.return_value = mock_response
        
        result = await plugin.run("test@example.com", session)
        
        assert result["email"] == "test@example.com"
        assert "TestBreach" in result["breaches"]
```

## Documentation

### Updating Documentation

- Update README.md for user-facing changes
- Add docstrings to all public functions
- Update API documentation
- Include usage examples
- Keep changelog updated

### Documentation Standards

- Use clear, concise language
- Include code examples
- Document all parameters and return values
- Add usage examples for new features
- Keep documentation up to date with code changes

## Security Considerations

- Never commit API keys or sensitive data
- Use environment variables for configuration
- Validate all user inputs
- Follow secure coding practices
- Report security issues privately

## API Key Management

- Use `.env` files for local development
- Document required API keys in README
- Provide fallback behavior when keys are missing
- Never log or expose API keys

## Release Process

1. Update version numbers
2. Update CHANGELOG.md
3. Create release notes
4. Tag the release
5. Update documentation

## Questions?

- Check existing issues and discussions
- Read the documentation thoroughly
- Ask questions in GitHub Discussions
- Contact maintainers for security issues

Thank you for contributing to the OSINT Master Tool! 🔍
