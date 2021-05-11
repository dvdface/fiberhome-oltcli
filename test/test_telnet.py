from oltcli.telnet import OLTTelnet

def test_olttelnet():
    telnet = OLTTelnet('10.182.33.210', 'GPON', 'GPON')
    telnet.connect()
    assert telnet.run('config') == ''
    telnet.disconnect()

def test_olttelnet_with():
    with OLTTelnet('10.182.33.210', 'GPON', 'GPON') as telnet:
        assert telnet.run('config') == ''
