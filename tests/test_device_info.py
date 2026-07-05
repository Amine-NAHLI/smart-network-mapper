from scanner import device_info

def test_get_device_info_mocked(monkeypatch):
    # Mock des dépendances système
    monkeypatch.setattr(device_info, "get_hostname_dns", lambda ip: "test-host.lan")
    monkeypatch.setattr(device_info, "estimate_os", lambda ip: "Linux/Unix")
    monkeypatch.setattr(device_info, "get_mac_arp", lambda ip: "AA:BB:CC:DD:EE:FF")
    
    # Test pour IP locale
    info = device_info.get_device_info("192.168.1.1")
    assert info["ip"] == "192.168.1.1"
    assert info["hostname"] == "test-host.lan"
    assert info["os"] == "Linux/Unix"
    assert info["mac"] == "AA:BB:CC:DD:EE:FF"
    
    # Test pour IP publique
    info_public = device_info.get_device_info("8.8.8.8", is_public=True)
    assert info_public["ip"] == "8.8.8.8"
    assert "Public IP" in info_public["mac"]
    assert info_public["hostname"] == "test-host.lan"
