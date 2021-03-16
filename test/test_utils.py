from oltcli.utils import *
from datetime import datetime

def test_auto_convert():

    assert auto_convert(None) == None

    assert auto_convert('10', 10) == 'null'

    assert auto_convert('10') == 10

    assert auto_convert('1.0') == 1.0

    assert type(auto_convert('2021-03-16 12:00:00')) == datetime

    assert auto_convert('0000-00-00 00:00:00') == None

    assert auto_convert('0x11') == 17


def test_validate_key():

    d = { 'name': 1}
    validate_key(d, 'name', int)


def test_list_to_str():

    assert list_to_str([1, 2, 3]) == '1 2 3'


def test_len_of_mask():

    assert len_of_mask('255.255.255.0') == 24

