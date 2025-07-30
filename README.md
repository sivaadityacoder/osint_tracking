# OSINT Master Tool 🔍

A powerful Open Source Intelligence (OSINT) investigation tool built with Python that provides comprehensive analysis across multiple intelligence sources.

## Features

- **Email Investigation**: Breach detection, public profile discovery
- **Domain Analysis**: WHOIS information, subdomain enumeration, reputation checks
- **IP Address Intelligence**: Geolocation, open ports, abuse reports
- **Username Reconnaissance**: Social media profile discovery across platforms
- **Async Processing**: High-performance concurrent investigations
- **Multiple Output Formats**: JSON and YAML support
- **Audit Logging**: Complete investigation history tracking
- **Extensible Plugin Architecture**: Easy to add new OSINT sources

## Installation

### Prerequisites

- Python 3.7+
- pip package manager

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/osint_master.git
cd osint_master
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Commands

#### Email Investigation
```bash
python main.py --email target@example.com --format json
```

#### Domain Analysis
```bash
python main.py --domain example.com --format yaml
```

#### IP Address Investigation
```bash
python main.py --ip 8.8.8.8
```

#### Username Reconnaissance
```bash
python main.py --username johndoe
```

#### Multiple Targets
```bash
python main.py --email user@domain.com --domain domain.com --ip 192.168.1.1 --username user123
```

#### With Audit Logging
```bash
python main.py --email target@example.com --audit-log investigations.log
```

### Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--email` | Investigate an email address | `--email admin@company.com` |
| `--domain` | Investigate a domain | `--domain example.com` |
| `--ip` | Investigate an IP address | `--ip 192.168.1.1` |
| `--username` | Investigate a username | `--username john_doe` |
| `--format` | Output format (json/yaml) | `--format yaml` |
| `--audit-log` | Audit log file path | `--audit-log audit.log` |

## Output Examples

### JSON Output
```json
{
  "email": {
    "email": "user@example.com",
    "breaches": ["Adobe", "LinkedIn"],
    "public_profiles": [
      "https://linkedin.com/in/user",
      "https://github.com/user"
    ],
    "notes": "Found in 2 data breaches"
  }
}
```

### YAML Output
```yaml
email:
  email: user@example.com
  breaches:
    - Adobe
    - LinkedIn
  public_profiles:
    - https://linkedin.com/in/user
    - https://github.com/user
  notes: Found in 2 data breaches
```

## OSINT Sources

### Current Integrations
- **HaveIBeenPwned**: Email breach detection
- **Shodan**: IP address and service information
- **Social Media**: Profile existence checks across platforms
- **DNS/WHOIS**: Domain registration and DNS records

### Planned Integrations
- VirusTotal API
- SecurityTrails
- Sherlock Project
- AbuseIPDB
- OSINT Framework sources

## Plugin Architecture

The tool uses a modular plugin system. Each plugin inherits from `PluginBase`:

```python
class CustomPlugin(PluginBase):
    name = "custom"
    description = "Custom OSINT source"
    
    async def run(self, query, session):
        # Your investigation logic here
        return {"custom_data": "results"}
```

## API Keys Configuration

Some features require API keys. Create a `.env` file:

```env
HIBP_API_KEY=your_haveibeenpwned_key
SHODAN_API_KEY=your_shodan_key
VIRUSTOTAL_API_KEY=your_virustotal_key
```

## Legal Notice

⚠️ **Important**: This tool is for educational and authorized security testing purposes only. Users are responsible for:

- Obtaining proper authorization before investigating targets
- Complying with local laws and regulations
- Respecting privacy and terms of service of investigated platforms
- Using the tool ethically and responsibly

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Adding New Plugins

1. Create a new plugin class inheriting from `PluginBase`
2. Implement the `run` method with async support
3. Add the plugin to the `load_plugins()` function
4. Update documentation and tests

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided "as is" without warranty. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have explicit permission before investigating any targets.

## Support

- 📧 Email: support@example.com
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/osint_master/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/yourusername/osint_master/discussions)

---

Made with ❤️ by the OSINT Community
