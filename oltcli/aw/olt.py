'''
Action words used to configure olt-related settigns
'''
from typing import NoReturn, Union

from ..utils import dotdict, break_frame_slot_port, validate_type
from ..cli import OLTCLI
from ..cli.common import AuthMode 

def add_port_vlan(olt_dev:dotdict, port:str, vid:Union[str, int], strip:bool=False) -> NoReturn:
    """add port vlan in uplink port

    Args:
        olt_dev (dotdict): olt want to set
        port (str): 端口号，形式为frameid/slotid/portid
        vid (str or int): VID， 支持1000 - 2000的配置，也支持单个的vid, 如 1000
        strip (bool, optional): 是否剥离tag，默认False，不剥离。True，剥离。
    """
    validate_type('strip', strip, bool)

    cli = OLTCLI.get(olt_dev)
    frame, slot, port = break_frame_slot_port(port)
    vid = str(vid).replace('-', ' to ')
    tag = 'tag' if strip == False else 'untag'

    cli.del_port_vlan(vid, slot, port)
    cli.set_port_vlan(vid, tag, slot, port)

def del_port_vlan(olt_dev:dotdict, port:str, vid:Union[str, int]) -> NoReturn:
    """删除 VLAN添加端口

    Args:
        olt_dev (dotdict): 要操作的OLT
        port (str): 端口号，形式为frameid/slotid/portid
        vid (str or int): VID， 支持1000 - 2000的配置，也支持单个的vid, 如 1000
    """
    cli = OLTCLI.get(olt_dev)
    frame, slot, port = break_frame_slot_port(port)
    vid = str(vid).replace('-', ' to ')

    cli.del_port_vlan(vid, slot, port)

def set_igmp_vlan(olt_dev:dotdict, vid:int) -> NoReturn:
    """配置组播VLAN

    Args:
        olt_dev (dotdict): 要操作的OLT
        vid (int): 要配置的组播VLAN
    """
    cli = OLTCLI.get(olt_dev)
    cli.set_igmp_vlan(vid)

def set_igmp_mode(olt_dev:dotdict, mode:str) -> NoReturn:
    """配置组播模式

    Args:
        olt_dev (dotdict): 要操作的OLT
        mode (str): 要配置的组播模式
    """
    cli = OLTCLI.get(olt_dev)
    cli.set_igmp_mode(mode)

def add_service_vlan(olt_dev:dotdict, service_name:str, begin_vid:int, end_vid:int, service_type:str) -> NoReturn:
    """配置局端外层VLAN数据

    Args:
        olt_dev (dotdict): 要操作的OLT
        name (str)): 业务VLAN名称
        begin_vid (int): 业务起始vid
        end_vid (int): 业务结束vid
        service_type (str): 业务的类型, 仅限'cnc', 'data', 'iptv', 'ngn', 'system', 'uplinksub', 'vod', 'voip'类型
    """
    cli = OLTCLI.get(olt_dev)
    cli.set_service_vlan(service_name, '%s - %s' % (begin_vid, end_vid), service_type)

def del_service_vlan(olt_dev:dotdict, service_name:str) -> NoReturn:
    """要删除的局端外层VLAN

    Args:
        olt_dev (dotdict): 要操作的OLT
        service_name (str): 局端外层VLAN名称
    """
    cli = OLTCLI.get(olt_dev)
    cli.del_service_vlan(service_name)

def add_static_route(olt_dev:dotdict, ip:str, mask:str, hop:str, metric:int=0) -> NoReturn:
    """配置网络层静态路由

    Args:
        olt_dev (dotdict): 要操作的OLT
        ip (str): 目的IP
        mask (str): 目的掩码
        hop (str): 下一跳
        metric (int): 权值
    """
    cli = OLTCLI.get(olt_dev)
    cli.set_static_route(hop, ip, mask, metric)

def del_static_route(olt_dev:dotdict, ip:str, mask:str, hop:str) -> NoReturn:
    """删除网络层静态路由

    Args:
        olt_dev (dotdict): 要操作的OLT
        ip (str): 目的IP
        mask (str): 目的掩码
        hop (str): 下一跳
    """
    cli = OLTCLI.get(olt_dev)
    cli.del_static_route(hop, ip, mask, metric=None)

def set_pon_auth_mode(olt_dev:dotdict, slot:int, port:int, mode:str) -> NoReturn:
    """配置PON口认证模式

    Args:
        olt_dev (dotdict): 要操作的OLT
        slot (int): 槽位号
        port (int): 端口号
        mode (str or AuthMode): 认证模式
    """
    cli = OLTCLI.get(olt_dev)
    cli.set_auth_mode(slot, port, AuthMode(mode) if type(mode) == str else mode)


# TODO:  上下行带宽模板

# TODO:  QinQ 模板

__all__ = [
    # VLAN业务
    'add_port_vlan',
    'del_port_vlan',

    # VLAN业务-局端VLAN
    'add_service_vlan',
    'del_service_vlan',

    # 组播
    'set_igmp_vlan',
    'set_igmp_mode',

    # 以太网基本配置
    'add_static_route',
    'del_static_route',

    # 公共配置
    # 公共配置-Pon口
    'set_pon_auth_mode'
]