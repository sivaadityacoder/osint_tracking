import argparse
import sys
import json
import yaml
import logging
import asyncio
import aiohttp
from datetime import datetime
from rich import print as rprint
from rich.console import Console

# --- Logger Setup ---
def setup_logger():
    logger = logging.getLogger("osint_master")
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    if not logger.handlers:
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger

# --- Plugin Base & Implementations ---
class PluginBase:
    name = ""
    description = ""
    async def run(self, query, session):
        raise NotImplementedError

class EmailPlugin(PluginBase):
    name = "email"
    description = "Investigates email addresses using OSINT sources."
    async def run(self, email, session):
        result = {
            "email": email,
            "breaches": [],
            "public_profiles": [
                f"https://linkedin.com/in/{email.split('@')[0]}",
                f"https://github.com/{email.split('@')[0]}"
            ],
            "notes": "Stub + real HaveIBeenPwned API integration."
        }
        try:
            async with session.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                                   headers={"hibp-api-key": "test", "user-agent": "osint-master"}) as resp:
                if resp.status == 200:
                    breaches = await resp.json()
                    result["breaches"] = [b["Name"] for b in breaches]
                elif resp.status == 404:
                    result["breaches"] = []
                else:
                    result["notes"] += f" HIBP status: {resp.status}"
        except Exception as e:
            result["notes"] += f" Error querying HaveIBeenPwned: {str(e)}"
        return result

class DomainPlugin(PluginBase):
    name = "domain"
    description = "Investigates domains using OSINT sources."
    async def run(self, domain, session):
        # This example uses a stub + basic whois info.
        result = {
            "domain": domain,
            "whois": "Sample WHOIS info (stub)",
            "subdomains": [f"blog.{domain}", f"mail.{domain}"],
            "reputation": "Clean",
            "notes": "Stub result. Add VirusTotal, SecurityTrails, etc. for real data."
        }
        return result

class IPPlugin(PluginBase):
    name = "ip"
    description = "Investigates IP addresses using OSINT sources."
    async def run(self, ip, session):
        # Example with stub + Shodan public info (API key required for more)
        result = {
            "ip": ip,
            "location": "Sample City, Country",
            "open_ports": [22, 80, 443],
            "reported_abuse": False,
            "notes": "Stub result. Add Shodan, AbuseIPDB, etc. for real data."
        }
        try:
            async with session.get(f"https://api.shodan.io/shodan/host/{ip}?key=demo") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result["open_ports"] = data.get("ports", [])
                    result["location"] = f"{data.get('city', '')}, {data.get('country_name', '')}"
                else:
                    result["notes"] += f" Shodan status: {resp.status}"
        except Exception as e:
            result["notes"] += f" Error querying Shodan: {str(e)}"
        return result

class UsernamePlugin(PluginBase):
    name = "username"
    description = "Investigates usernames across social platforms."
    async def run(self, username, session):
        # Stub + sample checks for existence on major platforms
        profiles = []
        platforms = [
            ("GitHub", f"https://github.com/{username}"),
            ("Twitter", f"https://twitter.com/{username}"),
            ("Instagram", f"https://instagram.com/{username}")
        ]
        for site, url in platforms:
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        profiles.append(url)
            except Exception:
                continue
        result = {
            "username": username,
            "profiles": profiles,
            "notes": "Stub + basic existence checks. Add Sherlock, SocialScan, etc. for real data."
        }
        return result

# --- Plugin Loader ---
def load_plugins():
    return {
        "email": EmailPlugin,
        "domain": DomainPlugin,
        "ip": IPPlugin,
        "username": UsernamePlugin,
    }

# --- Main ---
async def main_async(args):
    logger = setup_logger()
    plugins = load_plugins()
    queries = {
        "email": args.email,
        "domain": args.domain,
        "ip": args.ip,
        "username": args.username
    }
    results = {}
    async with aiohttp.ClientSession() as session:
        tasks = []
        for key, value in queries.items():
            if value and key in plugins:
                logger.info(f"Running {key} plugin for value: {value}")
                tasks.append((key, plugins[key]().run(value, session)))
        responses = await asyncio.gather(*(t[1] for t in tasks))
        for i, (key, _) in enumerate(tasks):
            results[key] = responses[i]
    if not results:
        logger.warning("No queries provided. Use --help for usage.")
        sys.exit(1)

    # Output formatting
    if args.format == "json":
        rprint(json.dumps(results, indent=2))
    else:
        rprint(yaml.safe_dump(results, sort_keys=False))

    # Audit log
    if args.audit_log:
        with open(args.audit_log, "a") as f:
            stamp = datetime.utcnow().isoformat()
            log_entry = {"timestamp": stamp, "results": results}
            if args.format == "json":
                f.write(json.dumps(log_entry) + "\n")
            else:
                f.write(yaml.safe_dump(log_entry) + "\n")

def main():
    parser = argparse.ArgumentParser(description="Best-in-world OSINT Master Tool")
    parser.add_argument("--email", help="Investigate an email address")
    parser.add_argument("--domain", help="Investigate a domain")
    parser.add_argument("--ip", help="Investigate an IP address")
    parser.add_argument("--username", help="Investigate a username")
    parser.add_argument("--format", choices=["json", "yaml"], default="json", help="Output format")
    parser.add_argument("--audit-log", help="Audit log file path")
    args = parser.parse_args()
    asyncio.run(main_async(args))

if __name__ == "__main__":
<<<<<<< HEAD
    main()
=======
    main()
>>>>>>> 2b517ada8512f9f43e9f19572d009c5ded8dbd61
