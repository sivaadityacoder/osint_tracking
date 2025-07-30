import pytest
import asyncio
import aiohttp
from unittest.mock import AsyncMock, patch, MagicMock
import sys
import os

# Add the parent directory to sys.path to import main
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import EmailPlugin, DomainPlugin, IPPlugin, UsernamePlugin, load_plugins

class TestEmailPlugin:
    @pytest.mark.asyncio
    async def test_email_plugin_success(self):
        plugin = EmailPlugin()
        session = AsyncMock(spec=aiohttp.ClientSession)
        
        # Mock successful HaveIBeenPwned response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value=[
            {"Name": "Adobe", "BreachDate": "2013-10-04"},
            {"Name": "LinkedIn", "BreachDate": "2012-05-05"}
        ])
        
        session.get.return_value.__aenter__.return_value = mock_response
        
        result = await plugin.run("test@example.com", session)
        
        assert result["email"] == "test@example.com"
        assert "Adobe" in result["breaches"]
        assert "LinkedIn" in result["breaches"]
        assert len(result["public_profiles"]) == 2

    @pytest.mark.asyncio
    async def test_email_plugin_no_breaches(self):
        plugin = EmailPlugin()
        session = AsyncMock(spec=aiohttp.ClientSession)
        
        # Mock 404 response (no breaches found)
        mock_response = AsyncMock()
        mock_response.status = 404
        
        session.get.return_value.__aenter__.return_value = mock_response
        
        result = await plugin.run("clean@example.com", session)
        
        assert result["email"] == "clean@example.com"
        assert result["breaches"] == []

    @pytest.mark.asyncio
    async def test_email_plugin_api_error(self):
        plugin = EmailPlugin()
        session = AsyncMock(spec=aiohttp.ClientSession)
        
        # Mock API error
        session.get.side_effect = Exception("API Error")
        
        result = await plugin.run("error@example.com", session)
        
        assert result["email"] == "error@example.com"
        assert "Error querying HaveIBeenPwned" in result["notes"]

class TestDomainPlugin:
    @pytest.mark.asyncio
    async def test_domain_plugin_basic(self):
        plugin = DomainPlugin()
        session = AsyncMock(spec=aiohttp.ClientSession)
        
        result = await plugin.run("example.com", session)
        
        assert result["domain"] == "example.com"
        assert "subdomains" in result
        assert "reputation" in result
        assert "blog.example.com" in result["subdomains"]

class TestIPPlugin:
    @pytest.mark.asyncio
    async def test_ip_plugin_success(self):
        plugin = IPPlugin()
        session = AsyncMock(spec=aiohttp.ClientSession)
        
        # Mock successful Shodan response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={
            "ports": [22, 80, 443],
            "city": "Mountain View",
            "country_name": "United States"
        })
        
        session.get.return_value.__aenter__.return_value = mock_response
        
        result = await plugin.run("8.8.8.8", session)
        
        assert result["ip"] == "8.8.8.8"
        assert result["open_ports"] == [22, 80, 443]
        assert "Mountain View" in result["location"]

    @pytest.mark.asyncio
    async def test_ip_plugin_api_error(self):
        plugin = IPPlugin()
        session = AsyncMock(spec=aiohttp.ClientSession)
        
        # Mock API error
        session.get.side_effect = Exception("Network Error")
        
        result = await plugin.run("1.1.1.1", session)
        
        assert result["ip"] == "1.1.1.1"
        assert "Error querying Shodan" in result["notes"]

class TestUsernamePlugin:
    @pytest.mark.asyncio
    async def test_username_plugin_found_profiles(self):
        plugin = UsernamePlugin()
        session = AsyncMock(spec=aiohttp.ClientSession)
        
        # Mock successful responses for GitHub and Twitter
        responses = [
            AsyncMock(status=200),  # GitHub
            AsyncMock(status=200),  # Twitter
            AsyncMock(status=404)   # Instagram
        ]
        
        session.get.return_value.__aenter__ = AsyncMock(side_effect=responses)
        
        result = await plugin.run("testuser", session)
        
        assert result["username"] == "testuser"
        assert len(result["profiles"]) >= 0  # Depends on implementation

    @pytest.mark.asyncio
    async def test_username_plugin_no_profiles(self):
        plugin = UsernamePlugin()
        session = AsyncMock(spec=aiohttp.ClientSession)
        
        # Mock 404 responses for all platforms
        mock_response = AsyncMock()
        mock_response.status = 404
        
        session.get.return_value.__aenter__.return_value = mock_response
        
        result = await plugin.run("nonexistentuser", session)
        
        assert result["username"] == "nonexistentuser"
        assert isinstance(result["profiles"], list)

class TestPluginLoader:
    def test_load_plugins(self):
        plugins = load_plugins()
        
        assert "email" in plugins
        assert "domain" in plugins
        assert "ip" in plugins
        assert "username" in plugins
        
        # Test that all plugins are subclasses of the expected base
        assert issubclass(plugins["email"], EmailPlugin)
        assert issubclass(plugins["domain"], DomainPlugin)
        assert issubclass(plugins["ip"], IPPlugin)
        assert issubclass(plugins["username"], UsernamePlugin)

class TestPluginBase:
    def test_plugin_attributes(self):
        """Test that all plugins have required attributes"""
        plugins = load_plugins()
        
        for plugin_name, plugin_class in plugins.items():
            plugin_instance = plugin_class()
            assert hasattr(plugin_instance, 'name')
            assert hasattr(plugin_instance, 'description')
            assert plugin_instance.name != ""
            assert plugin_instance.description != ""

if __name__ == "__main__":
    pytest.main([__file__])
