import pytest
from ai_engine.src.llm_provider import LLMProvider

@pytest.fixture
def provider():
    # Use empty provider to test fallback when no keys are available
    return LLMProvider(provider="none")

def test_command_parsing_wget(provider):
    # Test wget fallback parsing
    context = {"username": "root", "current_directory": "/root"}
    response = provider.generate_shell_response("wget http://test.com/payload.sh", context)
    assert "payload.sh" in response
    assert "200 OK" in response
    assert "saved" in response

def test_ai_fallback_command_not_found(provider):
    context = {"username": "root", "current_directory": "/root"}
    response = provider.generate_shell_response("made_up_command", context)
    assert "bash: made_up_command: command not found" in response

def test_ai_fallback_nmap(provider):
    context = {"username": "root"}
    response = provider.generate_shell_response("nmap 10.0.0.1", context)
    assert "Nmap 7.80" in response
    assert "open" in response
