from unittest.mock import patch

import iocage_lib.ioc_common as ioc_common

IFCONFIG_OUT = b"""epair0b: flags=8943<UP> mtu 1500
    ether 02:ff:60:00:01:02
    inet 192.168.0.10 netmask 0xffffff00 broadcast 192.168.0.255
"""

CONF = {
    'dhcp': 'on',
    'interfaces': 'vnet0:bridge0',
    'host_hostuuid': 'testjail',
}

@patch('iocage_lib.ioc_common.get_active_jails')
@patch('iocage_lib.ioc_common.su.check_output')
def test_retrieve_ip4_from_jls(mock_check_output, mock_active):
    mock_active.return_value = {
        'ioc-testjail': {'ip4.addr': 'vnet0|192.168.0.10/24'}
    }
    result = ioc_common.retrieve_ip4_for_jail(CONF, True)
    assert result == {'short_ip4': 'DHCP', 'full_ip4': 'vnet0|192.168.0.10/24'}
    mock_check_output.assert_not_called()

@patch('os.geteuid', return_value=0)
@patch('iocage_lib.ioc_common.su.check_output')
@patch('iocage_lib.ioc_common.get_active_jails', return_value={})
def test_retrieve_ip4_fallback_ifconfig(mock_active, mock_check_output, mock_euid):
    mock_check_output.return_value = IFCONFIG_OUT
    result = ioc_common.retrieve_ip4_for_jail(CONF, True)
    assert result == {'short_ip4': 'DHCP', 'full_ip4': 'epair0b|192.168.0.10'}
    mock_check_output.assert_called_once_with([
        'jexec', 'ioc-testjail', 'ifconfig', 'epair0b', 'inet'
    ])
