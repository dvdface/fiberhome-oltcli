'''
这里存放所有CLI模块所需的公共枚举值、函数
'''

from enum import Enum

class IGMPMode(Enum):
    """所有支持的IGMP模式
    """
    control = 'control' # 可控模式
    proxy_proxy = 'proxy-proxy' # 代理-代理模式
    snooping = 'snooping' # 侦听模式
    proxy_snooping = 'proxy-snooping' # 代理-侦听模式
    disable = 'disable' # 关闭模式

class DhcpOption(Enum):
    """用于dhcp option18/37/82或patch enable/disable命令
    """
    option18 = 'option18'
    option37 = 'option37'
    option82 = 'option82'
    patch = 'patch'

class WhitelistMode(Enum):
    """whitelist add命令所支持的所有授权模式。
    """
    phyid = 'phy-id'
    phyid_psw = 'phy-id+psw'
    logid = 'log-id'
    logid_psw = 'log-id+psw'
    password = 'password'


def get_whitelist_query_str(wlMode):
    """根据WhitelistMode的类型，返回对应的查询白名单的字符
    
    Args:
        wlMode (WhitelistMode): 白名单模式
    """
    if wlMode in [ WhitelistMode.phyid, WhitelistMode.phyid_psw ]:
        return 'phy-id'

    if wlMode in [ WhitelistMode.logid, WhitelistMode.logid_psw ]:
        return 'logic-id'
    
    if wlMode in [ WhitelistMode.password ]:
        return 'password'


class AuthMode(Enum):
    """用于port authentication-mode <mode>命令，设置授权模式
    """
    logid = 'log-id'
    logid_psw = 'log-id+psw'
    no_auth = 'no-auth'
    password = 'password'
    phyid_psw = 'phy-id+psw'
    phyid_o_logid_psw_o_psw = 'phy-id/log-id+psw/psw'
    phyid_o_logid_o_psw = 'phy-id/log-id/psw'
    phyid_o_psw = 'phy-id/psw'
    phyid = 'phyid'

class WanMode(Enum):
    
    tr069 = 'tr069'
    internet = 'internet'
    tr069_internet = 'tr069-internet'
    other = 'other'
    multi = 'multi'
    voip = 'voip'
    voip_internet = 'voip-internet'
    iptv = 'iptv'
    radius = 'radius'
    radius_internet = 'radius-internet'
    unicast_iptv = 'unicast-iptv'
    multicast_iptv = 'multicast-iptv'

class WanType(Enum):

    bridge = 'bridge'
    route = 'route'

class DSPMode(Enum):

    dhcp = 'dhcp'
    dhcp_remoteid ='dhcp-remoteid'
    static = 'static'
    pppoe = 'pppoe'

class PPPoEMode(Enum):

    auto = 'auto'       # 自动连接
    payload = 'payload' # 有流量的时候连接
    manual = 'manual'   # 手动连接


class Type(Enum):
    """规则类型
    """
    sa = 'sa' # 基于SA MAC地址
    da = 'da' # 基于DA MAC地址
    sip = 'sip' # 基于源IP地址
    dip = 'dip' # 基于目的IP地址
    vid = 'vid' # 基于VLAN ID
    sport = 'sport' # 基于L4的源Port
    dport = 'dport' # 基于L4的目的Port
    iptype = 'iptype' # 基于IP协议类型
    eth_type =  'eth_type' # 基于以太网
    tos =  'tos' # 基于IP ToS
    priority = 'priority' # 基于以太网优先级
    daipv6pre = 'daipv6pre' # 基于目的IPv6地址前缀
    saipv6pre  = 'saipv6pre' # 基于源IPv6地址前缀
    ipver = 'ipver' # 基于IP版本
    ipv6tra = 'ipv6tra' #  基于IPv6优先级字段分类
    ipv6fl = 'ipv6fl' # 基于IPv6流量标签
    ipv6nh = 'ipv6nh' # 基于下一包头(IPv6)

class Operator(Enum):
    """操作
    """
    equal = 0
    not_equal = 1
    less_than = 2
    greater_than = 3
    exist = 4
    not_exist = 5
    always = 6

class Direction(Enum):
    """流的类型
    """
    upstream = 'upstream'  # 上行流
    downstream = 'downstream' # 下行流

__all__ = [

    'IGMPMode',
    'DhcpOption',
    'WhitelistMode',
    'AuthMode',
    'WanMode',
    'WanType',
    'DSPMode',
    'PPPoEMode',
    
    'Direction',
    'Type',
    'Operator',

    'get_whitelist_query_str'
]