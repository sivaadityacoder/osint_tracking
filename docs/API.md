# API Documentation

## Plugin Architecture

The OSINT Master Tool uses a modular plugin architecture that allows easy extension with new OSINT sources.

### PluginBase Class

All plugins must inherit from the `PluginBase` class:

```python
class PluginBase:
    name = ""           # Plugin identifier
    description = ""    # Human-readable description
    
    async def run(self, query, session):
        """
        Execute the plugin's investigation logic.
        
        Args:
            query (str): The target to investigate
            session (aiohttp.ClientSession): HTTP session for API calls
            
        Returns:
            dict: Investigation results
            
        Raises:
            NotImplementedError: If not implemented by subclass
        """
        raise NotImplementedError
```

### Plugin Implementation Guidelines

#### 1. Plugin Structure

```python
class CustomPlugin(PluginBase):
    name = "custom"
    description = "Custom OSINT source integration"
    
    async def run(self, query: str, session: aiohttp.ClientSession) -> dict:
        """Implementation details"""
        return {
            "source": self.name,
            "query": query,
            "data": results,
            "timestamp": datetime.utcnow().isoformat(),
            "notes": "Additional information"
        }
```

#### 2. Error Handling

```python
async def run(self, query, session):
    try:
        async with session.get(f"https://api.example.com/{query}") as resp:
            if resp.status == 200:
                data = await resp.json()
                return {"success": True, "data": data}
            else:
                return {"success": False, "error": f"HTTP {resp.status}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
```

#### 3. Rate Limiting

```python
import asyncio

class RateLimitedPlugin(PluginBase):
    def __init__(self):
        self.last_request = 0
        self.min_interval = 1.0  # Minimum seconds between requests
    
    async def run(self, query, session):
        # Implement rate limiting
        now = asyncio.get_event_loop().time()
        elapsed = now - self.last_request
        if elapsed < self.min_interval:
            await asyncio.sleep(self.min_interval - elapsed)
        
        self.last_request = asyncio.get_event_loop().time()
        # Make API request...
```

## Core Plugins

### EmailPlugin

Investigates email addresses using multiple OSINT sources.

**Capabilities:**
- Breach detection via HaveIBeenPwned
- Public profile enumeration
- Social media account discovery

**API Response:**
```json
{
  "email": "user@example.com",
  "breaches": ["Adobe", "LinkedIn"],
  "public_profiles": [
    "https://linkedin.com/in/user",
    "https://github.com/user"
  ],
  "notes": "Additional context"
}
```

**Required API Keys:**
- `HIBP_API_KEY`: HaveIBeenPwned API key

### DomainPlugin

Analyzes domains for security and infrastructure information.

**Capabilities:**
- WHOIS information retrieval
- Subdomain enumeration
- Reputation checking
- DNS record analysis

**API Response:**
```json
{
  "domain": "example.com",
  "whois": "Registration details...",
  "subdomains": ["blog.example.com", "mail.example.com"],
  "reputation": "Clean",
  "dns_records": {
    "A": ["93.184.216.34"],
    "MX": ["mail.example.com"]
  },
  "notes": "Domain analysis complete"
}
```

### IPPlugin

Investigates IP addresses for geolocation, services, and reputation.

**Capabilities:**
- Geolocation information
- Open port scanning via Shodan
- Abuse reporting checks
- ISP and organization details

**API Response:**
```json
{
  "ip": "8.8.8.8",
  "location": "Mountain View, United States",
  "open_ports": [53, 443],
  "isp": "Google LLC",
  "reported_abuse": false,
  "services": [
    {"port": 53, "service": "dns", "version": "unknown"}
  ],
  "notes": "Google DNS server"
}
```

**Required API Keys:**
- `SHODAN_API_KEY`: Shodan API key

### UsernamePlugin

Searches for usernames across social media platforms.

**Capabilities:**
- Profile existence checking
- Social media account discovery
- Public information gathering

**API Response:**
```json
{
  "username": "johndoe",
  "profiles": [
    "https://github.com/johndoe",
    "https://twitter.com/johndoe"
  ],
  "platforms_checked": ["GitHub", "Twitter", "Instagram"],
  "found_on": ["GitHub", "Twitter"],
  "notes": "Profile analysis complete"
}
```

## Configuration

### Environment Variables

The tool supports configuration via environment variables:

```bash
# API Keys
HIBP_API_KEY=your_hibp_key
SHODAN_API_KEY=your_shodan_key
VIRUSTOTAL_API_KEY=your_virustotal_key

# General Settings
LOG_LEVEL=INFO
REQUEST_TIMEOUT=30
MAX_CONCURRENT_REQUESTS=10
```

### Loading Configuration

```python
import os
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv('HIBP_API_KEY')
timeout = int(os.getenv('REQUEST_TIMEOUT', 30))
```

## Async Processing

The tool uses async/await for concurrent processing:

```python
async def main_async(args):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for plugin_name, query in queries.items():
            if query:
                plugin = plugins[plugin_name]()
                tasks.append(plugin.run(query, session))
        
        results = await asyncio.gather(*tasks)
```

## Output Formats

### JSON Format

```json
{
  "email": {
    "email": "user@example.com",
    "breaches": ["Adobe"],
    "notes": "Found in 1 breach"
  },
  "domain": {
    "domain": "example.com",
    "reputation": "Clean"
  }
}
```

### YAML Format

```yaml
email:
  email: user@example.com
  breaches:
    - Adobe
  notes: Found in 1 breach
domain:
  domain: example.com
  reputation: Clean
```

## Audit Logging

The tool supports comprehensive audit logging:

```json
{
  "timestamp": "2025-07-30T10:30:00.000Z",
  "query_type": "email",
  "query_value": "user@example.com",
  "results": {
    "breaches_found": 1,
    "profiles_discovered": 2
  },
  "execution_time": 2.34,
  "success": true
}
```

## Error Handling

### Common Error Patterns

```python
# API Rate Limiting
if resp.status == 429:
    retry_after = int(resp.headers.get('Retry-After', 60))
    await asyncio.sleep(retry_after)
    # Retry request

# Invalid API Key
if resp.status == 401:
    logger.error(f"Invalid API key for {self.name}")
    return {"error": "Authentication failed"}

# Resource Not Found
if resp.status == 404:
    return {"found": False, "message": "No data available"}
```

### Exception Handling

```python
try:
    result = await self.make_api_call(query, session)
    return result
except asyncio.TimeoutError:
    return {"error": "Request timeout"}
except aiohttp.ClientError as e:
    return {"error": f"HTTP client error: {str(e)}"}
except Exception as e:
    logger.exception(f"Unexpected error in {self.name}")
    return {"error": f"Unexpected error: {str(e)}"}
```

## Testing

### Plugin Testing

```python
import pytest
from unittest.mock import AsyncMock

@pytest.mark.asyncio
async def test_plugin():
    plugin = CustomPlugin()
    session = AsyncMock()
    
    # Mock API response
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json.return_value = {"data": "test"}
    session.get.return_value.__aenter__.return_value = mock_response
    
    result = await plugin.run("test_query", session)
    
    assert result["success"] is True
    assert "data" in result
```

### Integration Testing

```python
@pytest.mark.asyncio
async def test_full_investigation():
    """Test complete investigation workflow"""
    async with aiohttp.ClientSession() as session:
        plugins = load_plugins()
        email_plugin = plugins["email"]()
        
        result = await email_plugin.run("test@example.com", session)
        
        assert "email" in result
        assert "breaches" in result
```

## Best Practices

1. **Rate Limiting**: Always implement rate limiting for API calls
2. **Error Handling**: Handle all possible HTTP status codes
3. **Timeout Management**: Set appropriate timeouts for requests
4. **Data Validation**: Validate input data before processing
5. **Logging**: Use comprehensive logging for debugging
6. **Security**: Never log sensitive data like API keys
7. **Documentation**: Document all plugin capabilities and limitations
