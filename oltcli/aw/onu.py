'''
配置ONU的Action Word
'''
from typing import NoReturn, Union
from ..utils import validate_type, dotdict
from ..cli import OLTCLI


def clear_port_service(olt_dev:dotdict, onu_dev:dotdict, onu_eth:int) -> NoReturn:
    """删除ONU 端口业务配置

    Args:
        olt_dev (dotdict): 要操作的OLT
        onu_dev (dotdict): 要操作的ONU
        onu_eth (int): 要操作的ONU网口号
    """
    cli = OLTCLI.get(olt_dev)
    cli.set_onu_port_vlan_service_count(onu_dev.sn, onu_eth, 0)

def add_port_service(olt_dev:dotdict, onu_dev:dotdict, onu_eth:int, **kargs) -> NoReturn:
    """ONU 端口业务配置

    Args:
        olt_dev (dotdict): 要操作的OLT
        onu_dev (dotdict): 要操作的ONU
        onu_eth (int): 要操作的ONU网口号
        tls (bool, optional): 配置TLS，可选。True，使能TLS; False，禁用TLS(默认)
        classification (list, optional): 业务区分，默认不区分。
        service_type (str, optional): 业务类型。unicast，单播(默认); multicast，多播
        cvlan_mode (str, optional): CVLAN模式。transparent，透传(默认)；tag，打标签
        cvlan_vid (int, optional): CVLAN VID。默认，无
        cvlan_cos (int, optional): 优先级,COS。默认，无
        cvlan_tpid (int, optional): 标签协议标识。默认，33024
        isp_vlan_vid (int, optional): SVLAN VID。默认， 无
        isp_vlan_cos (int, optional): SVLAN COS。默认，无
        upstream_bandwidth_profile (str, optional): 上行带宽模板。默认， 无
        downstream_bandwidth_profile (str, optional): 下行带宽模板。默认， 无
        dataservice_bandwidth_type (): 数据业务带宽类型。默认， 系统默认
        priority_queue (int, optional): 优先级队列。默认，0
        gem_port (int, optional): GEM Port。默认，0
        enable_translate (bool, optional): 使能翻译状态。默认，False
        translate_vid (int, optional): 翻译VID
        translate_cos (int, optional): 翻译优先级
        translate_tpid (int, optional): 翻译TPID
        enable_qinq (bool, optional): 使能QinQ状态
        qinq_profile (str, optional): QinQ模板
        service_vlan_name (str, optional): 业务VLAN名称
        svlan_vid (int, optional): 业务VLAN ID
        svlan_cos (int, optional): 业务VLAN 优先级
        svlan_tpid (int, optional): 业务VLAN TPID。默认，33024

    Returns:
        int : 所配置业务的索引号
    """
    cli = OLTCLI.get(olt_dev)

    service_count = cli.get_onu_port_vlan_service_count(onu_dev.sn, onu_eth)
    cli.set_onu_port_vlan_service_count(onu_dev.sn, onu_eth, service_count + 1)
    service_index = service_count + 1


    # 配置TLS
    if 'tls' in kargs.keys():
        validate_type('tls', kargs['tls'], bool)
        cli.set_onu_port_vlan_tls(onu_dev.sn, onu_eth,  service_index, kargs['tls'])

    # 配置 业务区分
    if 'classification' in kargs.keys():
        validate_type('classification', kargs['classification'], list)
        cli.set_onu_port_vlan_service_classification(onu_dev.sn, onu_eth, service_index, kargs['classification'])
    
    # 配置 业务类型(有就配置，没有就不配置，不配置默认一般是unicast)
    if 'service_type' in kargs.keys():
        validate_type('service_type', kargs['service_type'], str)
        cli.set_onu_port_vlan_service_type(onu_dev.sn, onu_eth, service_index, kargs['service_type']) 

    # 配置 CVLAN模式 部分
    cvlan_mode = kargs.get('cvlan_mode', 'transparent')
    cvlan_vid = kargs.get('cvlan_vid', 'null')
    cvlan_cos = kargs.get('cvlan_cos', 'null')
    cvlan_tpid = kargs.get('cvlan_tpid', 33024)
    cli.set_onu_port_vlan_service_vlan(onu_dev.sn, onu_eth, service_index, (cvlan_mode, cvlan_cos, cvlan_tpid, cvlan_vid))

    # TODO: ISP VLAN 和 COS

    # TODO: 上下行带宽模板

    # TODO: 数据业务带宽类型、优先级队列、GEM PORT

    # 翻译设置
    enable_translate = 'enable' if kargs.get('enable_translate', False) else 'disable'
    translate_vid = kargs.get('translate_vid', 'null')
    translate_cos = kargs.get('translate_cos', 'null')
    translate_tpid = kargs.get('translate_tpid', 33024)
    cli.set_onu_port_vlan_service_vlan(onu_dev.sn, onu_eth, service_index, ('translate', enable_translate, translate_cos, translate_tpid, translate_vid))
    
    # QinQ状态
    if 'enable_qinq' in kargs.keys():
        
        assert 'qinq_profile' in kargs.keys(), '使能QinQ时， qinq_profile不能为空'
        assert 'service_vlan_name' in kargs.keys(), '使能QinQ时， service_vlan_name不能为空'
        assert 'svlan_vid' in kargs.keys(), '使能QinQ时， svlan vid不能为空'
        assert 'svlan_cos' in kargs.keys(), '使能QinQ时， svlan cos不能为空'
        assert 'svlan_tpid' in kargs.keys(), '使能QinQ时，svlan tpid不能为空'

        enable_qinq = 'enable' if kargs['enable_qinq'] else 'disable'
        svlan_cos = kargs['svlan_cos']
        svlan_tpid = kargs['svlan_tpid']
        svlan_vid = kargs['svlan_vid']
        qinq_profile = kargs['qinq_profile']
        service_vlan_name = kargs['service_vlan_name']

        cli.set_onu_port_vlan_service_vlan(onu_dev.sn, onu_eth, service_index, ('qinq', enable_qinq, svlan_cos, svlan_tpid, svlan_vid, qinq_profile, service_vlan_name))

    return service_index


# TODO: WAN 配置



__all__ = [

    'clear_port_service',
    'add_port_service',

]