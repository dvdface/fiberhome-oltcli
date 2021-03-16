from oltcli.cli import OLTModel, OLTCLI

def test_oltcli():

    oltcli = OLTCLI.get(OLTModel.AN6000_17, '10.182.33.210', 'GEPON', 'GEPON')
    assert type(oltcli.get_authorization()) == list