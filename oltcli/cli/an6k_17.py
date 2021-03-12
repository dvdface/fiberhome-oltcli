'''
这里是AN6000-17型号OLT的OLTCLI实现模块
'''

from datetime import time
from dateutil.parser import parse

import re
import logging
import time

from ..utils import value, validate_type, run_by_thread_pool, list_to_str, validate_key, wait_for_true, validate_int_range, len_of_mask
from .common import *
from ..conn import Connection



type_str_to_int_value_map = {
    # 用于将show onuqinq-classification-profile返回的字符串转换为数值

    'Source MAC Address': 0,
    'Destination MAC Address': 1,
    'Source IPV4 Address': 2,
    'Destination IPV4 Address': 3,
    'VLAN ID': 4,
    'Ethernet TYPE': 5,
    'IP Protocol Type': 6,
    'COS': 7,
    'TOS': 8,
    'L4 Source Port': 9,
    'L4 Destination Port': 10,
    'Destination IPV6 Prefix': 11,
    'Source IPV6 Prefix': 12,
    'IP Version': 13,
    'IPV6 Traffic Class': 14, 
    'IPV6 Flow Label': 15,
    'IPV6 Next Header': 16
}

op_str_to_int_value_map = {
    # 用于将show onuqinq-classification-profile返回的字符串转换为数值

    '=': 0,
    '!=': 1,
    '<=': 2,
    '>=': 3,
    'Exist then match': 4, 
    'No exist then match': 5, 
    'Always match': 6
}

def type_str_to_int(strValue):
    """将show onuqinq-domain-profile返回的type字串转换为数值

    Args:
        strValue (str): type字符串
    
    Returns:
        int: 字符串对应的数值
    """
    return type_str_to_int_value_map[strValue]

def op_str_to_int(strValue):
    """将show onuqinq-domain-profile返回的op字串转换为数值

    Args:
        strValue (str): op字符串
    
    Returns:
        int: 字符串对应的数值
    """
    return op_str_to_int_value_map[strValue]

def onu_value_str_to_str(strValue, intFieldType):
    """转换show onuqinq-domain-profile返回的value字串

    Args:
        strValue (str): value字符串
        intFieldType (int): 该字符串对应的Field类型
    Returns:
        any: 处理后的字符串
    """
    # 0: Source MAC				    Source MAC Address 					00 00 00 00 00 00
    # 1: Destination MAC			Destination MAC Address				00 00 00 00 00 00
    # 2: Source IPv4				Source IPV4 Address					192.168.1.1
    # 3: Destination IPv4			Destination IPV4 Address			192.168.1.1
    # 4: Vlan ID					VLAN ID								1000
    # 5: Ethernet type			    Ethernet TYPE						11
    # 6: IP protocol type			IP Protocol Type					0b 00 00 00 00 00
    # 7: Ethernet priority		    COS									01 00 00 00 00 00
    # 8: TOS/DSCP					TOS									0b 00 00 00 00 00
    # 9: L4 source port			    L4 Source Port						54
    # 10: L4 destination port		L4 Destination Port					54
    # 11: Destination IPv6 prefix	Destination IPV6 Prefix				1:1:1:1:1:1:1:1
    # 12: Source IPv6 prefix		Source IPV6 Prefix					1:1:1:1:1:1:1:1
    # 13: IP version				IP Version							04
    # 14: IPv6 traffic class		IPV6 Traffic Class 					04 00 00 00 00 00
    # 15: IPv6 flow label			IPV6 Flow Label						00 00 04 57 00 00
    # 16: IPv6 next header		    IPV6 Next Header					0a 00 00 00 00 00

    if intFieldType in [0, 1, 2, 3, 4, 5, 9, 10, 11, 12]:
        return strValue.replace(' ', '')
    
    if intFieldType in [6, 7, 8, 13, 14, 15, 16]:
        strList = strValue.split(' ')
        # remove '00' in the head until meet no '00'
        while len(strList) != 0 and '00' == strList[0]:
            del strList[0]
        # remove '00' in the tail until meet no '00'
        while len(strList) != 0 and '00' == strList[-1]:
            del strList[-1]

        strValue = ''.join(strList)
        # if value is zero, strValue will be empty string, so we need put 0 here to avoid exception
        if strValue == '':
            strValue = '0'
        
        # return
        return int(strValue, 16)

def olt_value_str_to_str(strValue, intFieldId):
    """ convert value str in show oltqinq-domain to str value
    """
    # 1(Dst Mac)						00 00 00 00 00 00 00 00
    # 2(Src Mac)						00 00 00 00 00 00 00 00
    # 3(Ethernet Type)				    [ff ff] 00 00 00 00 00 00
    # 4(Vlan4)						    [ff ff] 00 00 00 00 00 00
    # 5(Vlan3)						    [ff ff] 00 00 00 00 00 00
    # 6(Vlan2)						    [ff ff] 00 00 00 00 00 00
    # 7(Vlan1)						    [ff ff] 00 00 00 00 00 00
    # 8(TOS)							[ff] 00 00 00 00 00 00 00
    # 10(TTL)							[ff] 00 00 00 00 00 00 00
    # 11(Protocol Type)				    [ff] 00 00 00 00 00 00 00
    # 12(Src IPv4)					    192.168.1.1
    # 13(Src IPv6)					    1:2:3:4:5:6:7:8
    # 14(Dst IPv4)					    192.168.1.1
    # 15(Dst IPv6)					    1:2:3:4:5:6:7:8
    # 16(L4 Src Port)					[ff ff] 00 00 00 00 00 00
    # 17(L4 Dst Port)					[ff ff] 00 00 00 00 00 00
    # 18(Cos4)						    [ff] 00 00 00 00 00 00 00
    # 19(Cos3)						    [ff] 00 00 00 00 00 00 00
    # 20(Cos2)						    [ff] 00 00 00 00 00 00 00
    # 21(Cos1)						    [ff] 00 00 00 00 00 00 00
    # 22(Dst IPv6 Prefix)				1:2:3:4:5:6:7:8
    # 23(Src IPv6 Prefix)				1:2:3:4:5:6:7:8
    # 24(IP Version)					[ff ff] 00 00 00 00 00 00
    # 25(IPv6 Traffic Class)			[ff] 00 00 00 00 00 00 00
    # 26(IPv6 Flow Label)				[ff ff] 00 00 00 00 00 00
    # 27(IPv6 Next Header)			    [ff] 00 00 00 00 00 00 00

    if intFieldId in [1, 2]:
        return strValue.replace(' ', '')[:-4]

    if intFieldId in [12, 13, 14, 15, 22, 23]:
        return strValue

    if intFieldId in [3, 4, 5, 6, 7, 8, 10, 11, 16, 17, 18, 19, 20, 21, 24, 25, 26, 27]:
        strList = strValue.split(' ')
        # remove '00' in the head until meet no '00'
        while len(strList) != 0 and '00' == strList[0]:
            del strList[0]
        # remove '00' in the tail until meet no '00'
        while len(strList) != 0 and '00' == strList[-1]:
            del strList[-1]
        
        strValue = ''.join(strList)
        # if value is zero, strValue will be empty string, so we need put 0 here to avoid exception
        if strValue == '':
            strValue = '0'
        
        # return
        return int(strValue, 16)
    
    assert False, "unknown field id: %s" % intFieldId

def str_to_bool(strStatus):
    """将'enable'，'disable'，'enabled'和'disabled'字符串转换为bool类型

    Args:
        strStatus: 待转换的字符串
    
    Returns:
        bool: 'enable'和'enabled'转换为True，'disable'和'disabled'字符串转换为False
    """
    validate_type('strStatus', strStatus, str)

    strStatus = strStatus.strip().lower()

    assert strStatus in ['enable','disable', 'enabled', 'disabled'], "仅支持'enable','disable', 'enabled', 'disabled'四种字符串转换，不支持%s" % strStatus
    
    if strStatus.find("enable") != -1:
        return True
    else:
        return False

def bool_to_str(boolStatus):
    """将bool值转换为'enable'或'disable'字符串

    Args:
        boolStatus (bool): 待转换的bool值
    Returns:
        str: True返回'enable'， False返回'disable'
    """
    validate_type('boolStatus', boolStatus, bool)

    if boolStatus:
        return "enable"
    else:
        return "disable"

def is_vlan_in_list(beginVlan, endVlan, tag, vlanList):
    """检查vlan列表中是否已经包含指定的vlan。如 1000, 1000, 'T'，已经包含在[(1000, 2000, 'T')]列表中。

    Args:
        beginVlan (int): 开始vlan
        endVlan (int): 结束vlan
        tag (str): vlan的模式，'T'或'U'
        vlanList (list): vlan列表。形式如， (1000, 2000, 'T')。

    Returns:
        bool: True，vlanList中包含它; False，vlanList不包含它。
    """
    isContained = False
    for v in vlanList:
        beginVlan, endVlan, vTag = v
        if vTag == tag:
            if beginVlan <= beginVlan and endVlan <= endVlan:
                isContained = True
    
    return isContained

def convert_port_vlan_str(strValue):
    """将port vlan字串转换成指定格式

    Args:
        strValue (str): port vlan的配置字符串。如， 1000 tag 1/9 2, 3、1000 to 2000 tag 1/9 2格式。

    Returns:
        tuple: (beginVlan, endVlan, tag, slotPortTupleList)格式的元组。如1000, 1000, tag, [(9, 2), (9, 3)]。
    """
    validate_type('strValue', strValue, str)

    vlanExp = re.compile('(\d+)\s+(to\s+(\d+)\s+)?(\w+)\s+\d+/(\d+)\s+([\d\s,]+)')

    beginVlan, _, endVlan, tag, slot, ports  = vlanExp.match(strValue)
    if endVlan == None:
        endVlan = beginVlan
    
    portList = [ ]
    for port in ports.split(","):
        portList.append((value(slot), value(port)))

    return value(beginVlan), value(endVlan), value(tag), portList 

def extract_port_authentication_mode(strValue):
    """处理show port authentication-mode命令返回的字符串。

    Args:
        strValue (str): show port authentication-mode命令返回的字符串。
    
    Returns:
        字典: 字典的键为(slot, pon)，值为授权模式。如， ret[slot, pon] = 'physical id'
    """
    # ======================================
    # slot 4 pon 8 ,auth mode is physical id.
    # ======================================
    # slot 4 pon 1 ,auth mode is physical id.
    # slot 4 pon 2 ,auth mode is physical id.
    # slot 4 pon 3 ,auth mode is physical id.
    # slot 4 pon 4 ,auth mode is physical id.
    # slot 4 pon 5 ,auth mode is physical id.
    # slot 4 pon 6 ,auth mode is physical id.
    # slot 4 pon 7 ,auth mode is physical id.
    # slot 4 pon 8 ,auth mode is physical id.
    # slot 4 pon 9 ,auth mode is physical id.
    # slot 4 pon 10 ,auth mode is physical id.
    # slot 4 pon 11 ,auth mode is physical id.
    # slot 4 pon 12 ,auth mode is physical id.
    # slot 4 pon 13 ,auth mode is physical id.
    # slot 4 pon 14 ,auth mode is physical id.
    # slot 4 pon 15 ,auth mode is physical id.
    # slot 4 pon 16 ,auth mode is physical id.
    # -----  PON AUTH, ITEM=16 -----
    # ======================================
    validate_type('strValue', strValue, str)
    
    lines = strValue.splitlines()

    portAuthExp = re.compile('slot (\d+) pon (\d+) ,auth mode is ([\w\s-+]+).')

    AuthModeDict = {

        # 用于将show port authentication-mode命令返回的授权模式字符串，映射为AuthMode中的模式
        "logical id": AuthMode.logid,
        "logical id + password": AuthMode.logid_psw,
        "no auth": AuthMode.no_auth,
        "physical password": AuthMode.password,
        "physical id + password": AuthMode.phyid_psw,
        "physical id or logical id + password or physical password": AuthMode.phyid_o_logid_psw_o_psw,
        "physical id or logical id or physical password": AuthMode.phyid_o_logid_o_psw,
        "physical id or physical password": AuthMode.phyid_o_psw,
        "physical id": AuthMode.phyid
    }


    ret = { }
    for line in lines:
        match = portAuthExp.match(line)
        if match:
            slot, pon, authMode = match.groups()
            ret[value(slot), value(pon)] = AuthModeDict[authMode]
        
    return ret

def extract_authorization(strValue):
    """处理show authorization命令得到的信息

    Args:
        strValue (str): show authorization命令得到的信息

    Returns:
        list: 包含信息的字典列表
    """
    # ====================================================================================================
    # -----  ONU Auth Table, Total ITEM = 5 -----

    # A: Authorized  P: Preauthorized  R: System Reserved

    # -----  ONU Auth Table, SLOT = 4, PON = 8, ITEM = 5 -----
    # Slot Pon Onu OnuType        ST Lic OST PhyId        PhyPwd     LogicId                  LogicPwd
    # ---- --- --- -------------- -- --- --- ------------ ---------- ------------------------ ------------
    # 4    8   1   5506-04-F1     A  0   up  FHTT033178b0
    # 4    8   64  HG6243C        A  0   up  FHTT92f445c8
    # 4    8   100 5506-10-A1     A  0   up  FHTT00010104
    # 4    8   127 5506-02-F      A  0   up  FHTT0274ab18
    # 4    8   128 5506-10-A1     A  0   up  FHTT000aae64
    # ====================================================================================================

    # A: Authorized  P: Preauthorized  R: System Reserved

    # -----  ONU Auth Table, SLOT = 4, PON = 8, ITEM = 5 -----
    # Slot Pon Onu OnuType        ST Lic OST PhyId        PhyPwd     LogicId                  LogicPwd
    # ---- --- --- -------------- -- --- --- ------------ ---------- ------------------------ ------------
    # 4    8   1   5506-04-F1     A  0   up  FHTT033178b0
    # 4    8   64  HG6243C        A  0   up  FHTT92f445c8
    # 4    8   100 5506-10-A1     A  0   up  FHTT00010104
    # 4    8   127 5506-02-F      A  0   up  FHTT0274ab18
    # 4    8   128 5506-10-A1     A  0   up  FHTT000aae64
    # ====================================================================================================
    validate_type('strValue', strValue, str)

    # 匹配标题
    titlesExp = re.compile('(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)')
    # 匹配值
    valuesExp = re.compile('([\d\s]{4,4})\s([\d\s]{3,3})\s([\d\s]{3,3})\s([\w\s-]{14,14})\s([\w\s]{2,2})\s([\d\s]{3,3})\s([\w\s]{3,3})\s([\w\s]{12,12})\s(.{10,10}\s)?(.{24,24}\s)?(.{12,12})?')

    ret = []
    lines = strValue.splitlines()
    titles = None
    for line in lines:
        match = titlesExp.match(line)
        if match:
            titles = match.groups()
            continue
        
        match = valuesExp.match(line)
        if match:
            values = match.groups()
            # 以字典形式存入
            ret.append({})
            for k, v in zip(titles, values):
                ret[-1][value(k)] = value(v, maxValue = 65535)
            continue
    
    return ret

def extract_discovery(strValue):
    """处理show discovery/show onu discovered得到的信息
    
    Args:
        strValue (str): show discovery/show onu discovered命令返回的字符串
    
    Returns:
        list: 包含字典的列表
    """
    # ====================================================================================
    # ----- ONU Unauth Table, SLOT = 4, PON = 8, ITEM = 1 -----
    # No  OnuType        PhyId        PhyPwd     LogicId                  LogicPwd     Why
    # --- -------------- ------------ ---------- ------------------------ ------------ ---
    # 1   HG6243C        FHTT91fbc5e8 fiberhome  fiberhome                fiberhome    1

    # Command executes success.
    # ====================================================================================
    # ----- ONU Unauth Table, SLOT = 4, PON = 8, ITEM = 1 -----
    # No  OnuType        PhyId        PhyPwd     LogicId                  LogicPwd     Why
    # --- -------------- ------------ ---------- ------------------------ ------------ ---
    # 1   HG6243C        FHTT91fbc5e8 fiberhome  fiberhome                fiberhome    1
    #
    # ====================================================================================
    # ----- ONU Unauth Table, SLOT = 4, PON = 8, ITEM = 6 -----
    # No  OnuType        PhyId        PhyPwd     LogicId                  LogicPwd     Why 
    # --- -------------- ------------ ---------- ------------------------ ------------ ---
    # 1   5506-04-F1     FHTT033178b0 fiberhome  fiberhome                fiberhome    1   
    # 2   HG6243C        FHTT92f445c8 fiberhome  fiberhome                fiberhome    1   
    # 3   5506-10-A1     FHTT00010104 fiberhome  fiberhome                fiberhome    1   
    # 4   5506-10-A1     FHTT000aae64            fiberhome                fiberhome    1   
    # 5   HG6243C        FHTT91fbc5e8 fiberhome  fiberhome                fiberhome    1   
    # 6   5506-02-F      FHTT0274ab18 wangran3   12345678                              1   
    # ====================================================================================
    
    validate_type('strValue', strValue, str)

    slotPortExp = re.compile('SLOT = (\d+), PON = (\d+)')
    titleExp = re.compile('(No)\s+(OnuType)\s+(PhyId)\s+(PhyPwd)\s+(LogicId)\s+(LogicPwd)\s+(Why)\s*')
    valueExp = re.compile('([\d\s]{3,3})\s([\w\s-]{14,14})\s([\w\s]{12,12})\s([\w\s]{10,10})\s([\w\s]{24,24})\s([\w\s]{12,12})\s([\d\s]{1,3})')

    lines = strValue.splitlines()

    ret = [ ]
    titles = None
    slot, port = None, None
    for line in lines:
        match = slotPortExp.search(line)
        if match:
            slot, port = match.groups()

        if titles == None:
            match = titleExp.match(line)
            if match:
                titles = match.groups()
                continue
        else:
            match = valueExp.match(line)
            if match:
                values = match.groups()
                ret.append({ })
                for k, v in zip(titles, values):
                    ret[-1][value(k)] = value(v)
                ret[-1]['SLOT'] = value(slot)
                ret[-1]['PON'] = value(port)
                continue

    return ret

def extract_auto_discover(strValue):
    """ 处理show onu auto-discover得到的信息

    Args:
        strValue(str): show onu auto-discover得到的字符串
    
    Returns:
        list: (slot, portNo, status, agingTime)元组组成的列表
    """
    validate_type('strValue', strValue, str)

    exp = re.compile('slot\s*(\d+)\s*pon\s*(\d+)\s*:\s*(\w+)\s*,\s*agingtime:\s*(\d+)\s*s')

    ret = [ ]
    for line in strValue.splitlines():
        match = exp.match(line)
        if match != None:
            slot, pon, status, agingTime = match.groups()
            ret.append((value(slot), value(pon), value(status), value(agingTime)))

    return ret

def extract_pon_auto_discover(strValue):
    """处理show onu auto-discover得到的信息
    
    Args:
        strValue(str): show onu auto-discover得到的信息
    
    Returns:
        tuple: status, agingTime组成的元组，其中status为bool类型
    """
    validate_type('strValue', strValue, str)

    exp = re.compile('auto-discover-onu:\s+(\w+),\s+agingtime:\s+(\d+)')

    for line in strValue.splitlines():
        match = exp.match(line)
        if match:
            strStatus, strAgingTime = match.groups()
            return value(strStatus), value(strAgingTime)
    
    raise RuntimeWarning("未发现Auto Discover数据")

def extract_manage_vlan(strValue):
    """处理show manage-vlan得到的信息
    
    Args:
        strValue(str): show manage-vlan得到的信息
    
    Returns:
        list: 包含管理Vlan字典的列表
    """
    # ------------------------------------
    # Manage name     : xx
    # ------------------------------------
    # Svlan           : 1000
    # Scos            : 7
    # Port            : 9:2[T]
    # Device          : sub
    # Unit            : 1000
    # Ethernet address: 48:f9:7c:e9:8a:e3
    # Total protocols : 0
    # RX packets      : 0
    # TX packets      : 8
    # RX bytes        : 0
    # TX bytes        : 704
    # MTU             : 0
    # ------------------------------------
    # Manage name     : yy
    # ------------------------------------
    # Svlan           : 2000
    # Scos            : 7
    # Port            : 9:2[T]
    # Device          : sub
    # Unit            : 2000
    # Ethernet address: 48:f9:7c:e9:8a:e3
    # Total protocols : 0
    # RX packets      : 0
    # TX packets      : 8
    # RX bytes        : 0
    # TX bytes        : 704
    # MTU             : 0

    validate_type('strValue', strValue, str)

    keyValueExp = re.compile('([\w\s]+):\s(.+)')

    ret = [ ]

    for line in strValue.splitlines():
        
        match = keyValueExp.match(line)
        if match:
            k, v = match.groups()
            k = value(k)
            v = value(v)

            if k == 'Manage name':
                ret.append({ })
            
            ret[-1][k] = v

    return ret

def extract_whitelist(strValue):
    """处理show whitelist命令得到的信息。

    Args:
        strValue (str): show whitelist命令得到的信息

    Returns:
        list: 包含处理后的信息列表
    """
    # 支持匹配6种输出

    validate_type('strValue', strValue, str)

    lines = strValue.splitlines()

    # 在config下运行show whitelist命令时
    #  ----- Physical Address Whitelist -----
    # Slot  Pon   Onu   Onu-Type       Phy-ID       Phy-Pwd    Used
    # ----- ----- ----- -------------- ------------ ---------- ----
    # 13    1     1     null           FHTT17f6c2d2            Y
    phy1TitleExp = re.compile('(Slot)\s+(Pon)\s+(Onu)\s+(Onu-Type)\s+(Phy-ID)\s+(Phy-Pwd)\s+(Used)')
    phy1ValuesExp = re.compile('([\d\s]{5,5})\s([\d\s]{5,5})\s([\d\s]{5,5})\s([\w\s-]{14,14})\s([\w\s]{12,12})\s([\w\d\s]{10,10})\s([\w\s]{1,4})')

    #  ----- Physical SN Whitelist-----
    # PHYID        PHYPWD     SLOT  PON   ONU   TYPE           EN  USED
    # ------------ ---------- ----- ----- ----- -------------- --- ----
    # FHTT000aae64            4     8     1     5506-10-A1     EN  YES
    # --------------------------------
    # SLOT: 4 PON: 8 ITEM: 1
    phy2TitleExp = re.compile('(PHYID)\s+(PHYPWD)\s+(SLOT)\s+(PON)\s+(ONU)\s+(TYPE)\s+(EN)\s+USED')
    phy2ValuesExp = re.compile('([\w\s]{12,12})\s([\w\s]{10,10})\s([\d\s]{5,5})\s([\d\s]{5,5})\s([\d\s]{5,5})\s([\w\s-]{14,14})\s([\w\s]{3,3})\s([\w\s]{1,4})')

    #  ----- Logic SN Whitelist-----
    # Slot  Pon   Onu   Onu-Type       Logic-Id                 Logic-Pwd    En Used
    # ----- ----- ----- -------------- ------------------------ ------------ -- ----
    # 13    1     2     null           FHTT17f6c2d2                          Y  Y
    log1TitleExp = re.compile('(Slot)\s+(Pon)\s+(Onu)\s+(Onu-Type)\s+(Logic-Id)\s+(Logic-Pwd)\s+(En)\s+(Used)')
    log1ValueExp = re.compile('([\d\s]{5,5})\s([\d\s]{5,5})\s([\d\s]{5,5})\s([\w\s-]{14,14})\s([\w\s]{24,24})\s([\w\s]{12,12})\s([\w\s]{2,2})\s([\w\s]{1,4})')

    # ----- Logical SN Whitelist-----
    # LOGICId                  LOGICPWD     SLOT  PON   ONU   TYPE           EN  USED
    # ------------------------ ------------ ----- ----- ----- -------------- --- ----
    # FHTT000aae64                          4     8     2     5506-10-A1     EN  YES
    # --------------------------------
    # SLOT: 4 PON: 8 ITEM: 1
    log2TitleExp = re.compile('(LOGICId)\s+(LOGICPWD)\s+(SLOT)\s+(PON)\s+(ONU)\s+(TYPE)\s+(EN)\s+(USED)')
    log2ValueExp = re.compile('([\w\s]{24,24})\s([\w\s]{12,12})\s([\d\s]{5,5})\s([\d\s]{5,5})\s([\d\s]{5,5})\s([\w\s-]{14,14})\s([\w\s]{3,3})\s([\w\s]{1,4})')

    #  ----- Physical Password Whitelist -----
    # Slot  Pon   Onu   Onu-Type       Phy-Pwd    En Used
    # ----- ----- ----- -------------- ---------- -- ----
    # 65535 65535 65535 null           123456     Y  N
    pwd1TitleExp = re.compile('(Slot)\s+(Pon)\s+(Onu)\s+(Onu-Type)\s+(Phy-Pwd)\s+(En)\s+(Used)')
    pwd1ValueExp = re.compile('([\d\s]{5,5})\s([\d\s]{5,5})\s([\d\s]{5,5})\s([\w\s-]{14,14})\s([\w\s]{10,10})\s([\w\s]{2,2})\s([\w\s]{1,4})')

    # ----- Physical Password Whitelist-----
    # PHYPWD     SLOT  PON   ONU   TYPE           EN  USED
    # ---------- ----- ----- ----- -------------- --- ----
    # 1234567890 4     8     3     5506-10-A1     EN  YES
    # --------------------------------
    # SLOT: 4 PON: 8 ITEM: 1
    pwd2TitleExp = re.compile('(PHYPWD)\s+(SLOT)\s+(PON)\s+(ONU)\s+(TYPE)\s+(EN)\s+(USED)')
    # '123456789a 4     8     65535 5506-10-A1     EN  NO   '
    pwd2ValueExp = re.compile('([\w\s]{10,10})\s([\d\s]{5,5})\s([\d\s]{5,5})\s([\d\s]{5,5})\s([\w\s-]{14,14})\s([\w\s]{3,3})\s([\w\s]{1,4})')

    exps = [(phy1TitleExp, phy1ValuesExp),
            (phy2TitleExp, phy2ValuesExp),
            (log1TitleExp, log1ValueExp),
            (log2TitleExp, log2ValueExp),
            (pwd1TitleExp, pwd1ValueExp),
            (pwd2TitleExp, pwd2ValueExp)]

    ret = [ ]
    titles = None
    valueExp = None
    for line in lines:
        if titles == None:
            # 先看看匹配到哪种标题，然后再用标题对应的抽取值的正则表达式去提取
            for tExp, vExp in exps:
                match = tExp.match(line)
                if match != None:
                    titles = match.groups()
                    valueExp = vExp
                    break

        else:
            # 确定之后，用该种正则表达式进行匹配
            match = valueExp.match(line)
            if match:
                values = match.groups()
                ret.append({ })
                for k, v in zip(titles, values):
                    ret[-1][value(k)] = value(v)

    return ret

def extract_last_reg_status_change(strValue):
    """处理show onu last-reg-status-change命令得到的数据。其中，时间若为0000-00-00 00:00:00，将会转换为None。

    Args:
        strValue (str): show onu last-reg-status-change命令得到的数据
    
    Returns:
        list: 字典列表。
    """
    # SLOT PON ONU LAST_OFF_TIME LAST_ON_TIME
    # 4    8   1   Last Off Time = 0000-00-00 00:00:00,Last On Time = 2020-09-22 14:09:29.
    # SLOT PON ONU LAST_OFF_TIME LAST_ON_TIME
    # 4    8   64  Last Off Time = 0000-00-00 00:00:00,Last On Time = 2020-09-22 14:09:30.
    # SLOT PON ONU LAST_OFF_TIME LAST_ON_TIME
    # 4    8   65  Last Off Time = 0000-00-00 00:00:00,Last On Time = 2020-09-22 14:09:29.
    # SLOT PON ONU LAST_OFF_TIME LAST_ON_TIME
    # 4    8   100 Last Off Time = 0000-00-00 00:00:00,Last On Time = 0000-00-00 00:00:00.
    # SLOT PON ONU LAST_OFF_TIME LAST_ON_TIME
    # 4    8   128 Last Off Time = 0000-00-00 00:00:00,Last On Time = 2020-09-22 14:09:30.
    validate_type('strValue', strValue, str)
    lines = strValue.splitlines()

    titles = ['SLOT', 'PON', 'ONU', 'LAST_OFF_TIME', 'LAST_ON_TIME']
    valuesExp = re.compile("(\d+)\s+(\d+)\s+(\d+)\s+Last Off Time = (\d{4,4}\-\d{2,2}\-\d{2,2}\s\d{2,2}:\d{2,2}:\d{2,2}),Last On Time = (\d{4,4}\-\d{2,2}\-\d{2,2}\s\d{2,2}:\d{2,2}:\d{2,2})\.")
    
    ret = [ ]
    for line in lines:
        match = valuesExp.match(line)
        if match:
            values = match.groups()
            ret.append({ })
            for k, v in zip(titles, values):
                ret[-1][value(k)] = value(v)
    
    return ret

def extract_dhcp_state(strValue):
    """处理show dhcp state命令得到的数据

    Args:
        strValue (str): show dhcp state命令得到的数据

    Returns:
        dict: 包含DHCP状态信息的字典
    """
    # DHCP option82  : disabled
    # DHCP option18  : enabled
    # DHCP option37  : disabled
    # EPON DHCP Patch   : disabled
    # EPON ARP Patch    : disabled
    validate_type('strValue', strValue, str)

    ret = { }
    for line in strValue.splitlines():
        key, value = line.split(":")
        ret[key.strip()] = value.strip()
    
    return ret

def extract_onu_port_vlan(strValue):
    """处理show onu port vlan得到的信息。

    Args:
        strValue (str): show onu port vlan得到的信息。

    Returns:
        list: 包含Port Vlan信息的列表
    """
    # NO.  SL/LI/ONU PORT ID TYPE  MODE CVID COS  TPID  TVID COS  TPID  SVID COS  TPID  PVID COS  SRVTYPE PRIQUE  GEMPORT
    # ====================================================================================================================
    # 1    4 /8 /1   1    1  unica tran null null 33024 null null null  null null null  null null default default default
    validate_type('strValue', strValue, str)

    ret = [ ]
    titles = ['NO', 'SL', 'LI', 'ONU', 'PORT', 'ID', 'TYPE', 'MODE', 'CVID', 'CCOS', 'CTPID', 'TVID', 'TCOS', 'TTPID', 'SVID', 'SCOS', 'STPID', 'PVID', 'PCOS', 'SRVTYPE', 'PRIQUE', 'GEMPORT']
    regexExp = re.compile("(\w+)\s+(\w+)\s+/(\w+)\s+/(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)")
    for line in strValue.splitlines():
        match = regexExp.match(line)
        if match != None:
            ret.append({})
            for k, v in zip(titles, match.groups()):
                ret[-1][k] = value(v)

    return ret

def extract_card_info(strValue):
    """处理show card info得到的信息

    Args:
        strValue (str): show card info得到的信息
    
    Return:
        list : 包含卡信息的字典列表
    """
    # ---------------------AN6000-17---------------------
    # CARD   EXIST   CONFIG   DETECT    DETAIL
    # 1     ---      ---      ---         ---
    # 2     ---      ---      ---         ---
    # 3     ---      ---      ---         ---
    # 4     ---      ---      ---         ---
    # 5     ---      ---      ---         ---
    # 6     ---      ---      ---         ---
    # 7     ---      ---      ---         ---
    # 8     ---      ---      ---         ---
    # 9     YES     HSCA     HSCA     MATCH/M
    # 10     ---     HSCA      ---         ---

    # ---------------------AN6000-17---------------------
    # CARD   EXIST   CONFIG   DETECT    DETAIL    BLOCK
    # 1     ---      ---      ---         ---         ---
    # 2     ---      ---      ---         ---         ---
    # 3     ---      ---      ---         ---         ---
    # 4     YES     GPOA     GPOA       MATCH         OFF
    # 5     ---      ---      ---         ---         ---
    # 6     ---      ---      ---         ---         ---
    # 7     ---      ---      ---         ---         ---
    # 8     ---      ---      ---         ---         ---
    # 9     YES     HSCA     HSCA     MATCH/M         ---
    # 10     ---     HSCA      ---         ---         ---
    validate_type('strValue', strValue, str)

    lines = strValue.splitlines()

    titlesExp = re.compile('(CARD)\s+(EXIST)\s+(CONFIG)\s+(DETECT)\s+(DETAIL)\s*(BLOCK)?')
    valuesExp = re.compile('(\d+)\s+([\w-]+)\s+([\w-]+)\s+([\w-]+)\s+([\w-\/]+)\s*([\w-]+)?')
    
    ret = [ ]
    titles = None
    for line in lines:
        if titles == None:
            match = titlesExp.match(line)
            if match:
                titles = match.groups()
                continue
        else:
            match = valuesExp.match(line)
            if match:
                values = match.groups()
                ret.append({ })
                for k, v in zip(titles, values):
                    if k != None:
                        ret[-1][value(k)] = value(v)
                continue

    return ret

def extract_onu_port_status(strValue):
    """处理show onu port status命令得到的信息

    Args:
        strValue (str): show onu port status命令得到的信息

    Returns:
        list: 包含端口信息的字典列表
    """
    # ----- ONU FE PORT STATUS -----
    # SLOT:4 PON:8 ONU:1  ,  ITEM=4

    # PORT ID = 1
    # PORT CONNECT    : Linked
    # FLOW CONTROL    : disable
    # PORT PHY STATE  : enable
    # AUTO NEGOTIATE  : enable
    # PORT RATE       : 1000M
    # PORT CONNECT    : full
    # LOOPBACK STATUS : normal

    # PORT ID = 2
    # PORT CONNECT    : Linked
    # FLOW CONTROL    : disable
    # PORT PHY STATE  : enable
    # AUTO NEGOTIATE  : enable
    # PORT RATE       : 1000M
    # PORT CONNECT    : full
    # LOOPBACK STATUS : normal

    # PORT ID = 3
    # PORT CONNECT    : Not Linked
    # FLOW CONTROL    : disable
    # PORT PHY STATE  : enable
    # AUTO NEGOTIATE  : enable
    # PORT RATE       : 10M
    # PORT CONNECT    : half
    # LOOPBACK STATUS : normal

    # PORT ID = 4
    # PORT CONNECT    : Linked
    # FLOW CONTROL    : disable
    # PORT PHY STATE  : enable
    # AUTO NEGOTIATE  : enable
    # PORT RATE       : 1000M
    # PORT CONNECT    : full
    # LOOPBACK STATUS : normal

    validate_type('strValue', strValue, str)

    summaryExp = re.compile('SLOT:(\d+)\s*PON:(\d+)\s*ONU:(\d+)\s*,\s*ITEM=(\d+)')
    portIdExp = re.compile('PORT\s+ID\s+=\s+(\d+)')
    keyValueExp = re.compile('(.+):(.+)')
    
    lines = strValue.splitlines()

    ret = { }
    for line in lines:
        match = summaryExp.match(line)
        if match:
            slot, pon, onu, item = match.groups()
            ret['SLOT'] = value(slot)
            ret['PON'] = value(pon)
            ret['ONU'] = value(onu)
            ret['ITEM'] = value(item)
            ret['PORT'] = [ ]
            continue
        
        match = portIdExp.match(line)
        if match:
            portId = match.groups()[0]
            ret['PORT'].append({ })
            ret['PORT'][-1]['PORT ID'] = value(portId)
            continue
        
        match = keyValueExp.match(line)
        if match:
            k, v = match.groups()
            if value(k) not in ret['PORT'][-1].keys():
                ret['PORT'][-1][value(k)] = value(v)
            else:
                # 有两个PORT CONNECT， 需要把后一个换个名字
                ret['PORT'][-1]['PORT MODE'] = value(v)
            continue

    return ret

def extract_igmp_vlan(strValue):
    """处理show igmp vlan命令得到的数据

    Args:
        strValue (str): show igmp vlan命令得到的数据

    Returns:
        dict: 包含igmp vlan信息的字典
    """
    # ========================================
    # Version                  :V0
    # Proxy ip address         :0.0.0.0
    # SSM ip address           :0.0.0.0
    # SSM ip mask              :0.0.0.0
    # General Member Interval  :0
    # Robustness               :0
    # QueryInterval            :0
    # Query response interval  :0
    # Last member query interval:0
    # Last member query count  :0
    # Fast Leave               :disable

    # Host-side Group Reserved :0
    # ALL Group Reserved       :0
    # Recieve Jions            :0
    # Recieve Leaves           :0
    # igi->igi_cflags          :0x0
    # igi->igi_sflags          :0x0
    # ========================================
    validate_type('strValue', strValue, str)

    regexExp = re.compile("(.+):(.+)")

    lines = strValue.splitlines()

    ret = { }
    for line in lines:
        match = regexExp.match(line)
        if match != None:
            k, v = match.groups()
            ret[value(k)] = value(v)

    return ret

def extract_port_vlan(strValue):
    """处理show port vlan得到的数据

    Args:
        strValue (str): show port vlan得到的数据

    Returns:
        list: 元组列表。形式如，[(startVlan, endVlan, "U"), [(startVlan, endVlan, "T"),...]。
    """
    # port  9:2,
    # vlan(optin):
    # 1000(U) .
    # 1251 ~ 1254(T).
    # 3049 ~ 3049(T).

    validate_type('strValue', strValue, str)

    vlanExp = re.compile('(\d+)\s?~?\s?(\d+)?\(([UT])\)')

    lines = strValue.splitlines()

    ret = [ ]
    for line in lines:
        
        match = vlanExp.match(line)
        if match:
            beginVlan, endVlan, tag = match.groups()
            if endVlan == None:
                endVlan = beginVlan

            ret.append((value(beginVlan), value(endVlan), value(tag)))
    
    return ret

def extract_wan_cfg(strValue):
    """提取show onu wan-cfg命令得到的信息

    Args:
        strValue (str): show onu wan-cfg命令得到的信息

    Return:
        dict: 包含wan cfg信息的字典
    """
    validate_type('strValue', strValue, str)

    ret = None

    regexExp0 = re.compile("slot_out \d+ \d+ \d+ index \d+ no wancfg,ret -?\d+.")
    if regexExp0.search(strValue) != None:
        return ret

    # show wancfg:slot 4 8 1 2 wan_name INTERNET_R_VID_2000 INTERNET route vlan 2000 cos 4 nat enable qos disable upnp disable DSP pppoe 0 mode auto fiberhome fiberhome xxx transparent translate disable tvlan 65535 tcos 65535 qinq disable 33024 65535 bind item 4 1   2   3   101
    # show wancfg:slot 4 8 1 1 wan_name INTERNET_R_VID_1000 INTERNET route vlan 1000 cos 4 nat enable qos enable upnp disable transparent translate disable tvlan 65535 tcos 65535 qinq disable 33024 65535 65535 bind item 4 1 2 3 101
   
    mandatoryPartExp = re.compile('show wancfg:slot\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+wan_name\s+(\w+)\s+(\w+)\s+(\w+)\s+vlan\s+(\d+)\s+cos\s+(\d+)\s+nat\s+(\w+)\s+qos\s+(\w+)\s+upnp\s+(\w+)\s+')
    # DSP\s+(\w+)\s+(\d+)\s+mode\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+
    pppoeDSPExp = re.compile('DSP\s+(\w+)\s+(\d+)\s+mode\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+')
    dhcpDSPExp = re.compile('DSP\s+(\w+)')
    staticDSPExp = re.compile('DSP\s+(\w+)\s+ip\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)')
    vlanmodeExp = re.compile('(\w+)\s+translate\s+(\w+)\s+tvlan\s+(\d+)\s+tcos\s+(\d+)\s+qinq\s+(\w+)\s+(\d+)\s+(\d+)\s+(\d+)\s+')
    entriesExp = re.compile('bind\s+item\s+(\d+)\s+([\d\s]+)?')

    if mandatoryPartExp.match(strValue) != None:

        if ret == None:
            ret = {}
        
        slot, port, onuId, index, name, mode, type, wvid, wcos, nat, qos, upnp = mandatoryPartExp.match(strValue).groups()
        
        ret['slot'] = value(slot)
        ret['port'] = value(port)
        ret['onuId'] = value(onuId)
        ret['index'] = value(index)
        ret['name'] = value(name)
        ret['mode'] = WanMode(mode.lower())
        ret['type'] = WanType(type.lower())
        ret['wvid'] = value(wvid)
        ret['wcos'] = value(wcos)
        ret['nat'] = value(nat)
        ret['qos'] = value(qos)
        ret['upnp'] = value(upnp)

    if vlanmodeExp.search(strValue) != None:

        tag, translate, tvlan, tcos, qinq, stpid, svlan, scos = vlanmodeExp.search(strValue).groups()
        
        ret['vlanmode'] = tag.lower() 
        ret['tvlan'] = translate
        ret['tvid'] = value(tvlan)
        ret['tcos'] = value(tcos)
        ret['qinq'] = qinq
        ret['stpid'] = value(stpid)
        ret['svlan'] = value(svlan)
        ret['scos'] = value(scos)

    if ret != None and 'dsp' not in ret.keys() and pppoeDSPExp.search(strValue) != None:
        
        dsp, proxy, pppoemode, username, password, servername = pppoeDSPExp.search(strValue).groups() 

        ret['dsp'] = DSPMode(dsp.lower())
        ret['proxy'] = 'enable' if proxy == '1' else 'disable'
        ret['pppoemode'] = PPPoEMode(pppoemode.lower())
        ret['username'] = value(username)
        ret['password'] = value(password)
        ret['servername'] = value(servername)

    if ret != None and 'dsp' not in ret.keys() and staticDSPExp.search(strValue) != None:
        
        dsp, ip, mask, gate, master, slave = staticDSPExp.search(strValue).groups()
        ret['dsp'] = DSPMode(dsp.lower())
        ret['ip'] = value(ip)
        ret['mask'] = value(mask)
        ret['gate'] = value(gate)
        ret['master'] = value(master)
        ret['slave'] = value(slave)

    if ret != None and 'dsp' not in ret.keys() and dhcpDSPExp.search(strValue) != None:
        
        dsp = dhcpDSPExp.search(strValue).groups()
        ret['dsp'] = DSPMode(dsp.lower())

    if ret != None and 'dsp' not in ret.keys():
        ret['dsp'] = DSPMode.dhcp_remoteid
        ret['remoteid'] = 'n/a'

    ret['fe'] = [ ]
    ret['ssid'] = [ ]
    if entriesExp.search(strValue) != None:

        if ret == None:
            ret = { }

        itemsCount, itemsValue  = entriesExp.search(strValue).groups()
        if int(itemsCount) != 0:

            feRegexExp = re.compile('^(\d)$')
            ssidRegexExp = re.compile('^10(\d)$')
            for v in re.split('\s+', itemsValue):
                if None != feRegexExp.match(v):
                    ret['fe'].append('fe%s' % v)
                elif None != ssidRegexExp.match(v):
                    ret['ssid'].append('ssid%s' % ssidRegexExp.match(v).groups()[0])
                elif '' == v:
                    continue
                else:
                    assert False, "未知的数值: '%s'(%s)" % (v, re.split('\s+', itemsValue))

    if ret == None:
        logging.getLogger().warning('未匹配到数据:\n%s' % strValue)
    
    return ret

def extract_igmp_mode_info(strValue):
    """提取show igmp mode命令信息

    Args:
        strValue(str): show igmp mode命令信息
    
    Returns:
        dict: 包含IGMP信息的字典
    """
    # system is running in IGMPv1/v2 proxy/snooping protocol
    # IGMP/MLD Mode      :  snooping
    # Robustness variable       :  2
    # Group membership interval :  260
    # Last member query interval:  1
    # Last member query count   :  2
    # Query interval            :  125
    # Query response interval   :  10

    validate_type('strValue', strValue, str)

    keyValueExp = re.compile('\s*(.+)\s*:\s*(.+)\s*')
    
    ret = { }
    for line in strValue.splitlines():
        match = keyValueExp.match(line)
        if match != None:
            key, value = match.groups()
            ret[key.strip()] = value.strip()
    
    return ret

def extract_onu_statistics(strValue):
    """提取show onu statistics命令的信息

    Args:
        strValue (str): show onu statistics命令的信息

    Returns:
        dict: 包含ONU统计信息的字典
    """
    # buf:0x8cdcddc4,len448,prtcl:0, lv:4,obj:4/8/4 type:4, order:0.
    # From 2020-11-10 14:46:04 To 0000-00-00 00:00:00
    # UPOctetsTransferred             :               0 (BYTEs)
    # UP TotalFrame                   :               0 (PKTs)
    # UP UnicastFrames                :               0 (PKTs)
    # UP BroadcastFrames              :               0 (PKTs)
    # UP MulticastFrames              :               0 (PKTs)
    # UP CRC-32Errors                 :               0 (PKTs)
    # UPUndersizeFrames               :               0 (PKTs)
    # UPOversizeFrames                :               0 (PKTs)
    # UPCollisions                    :               0 (PKTs)
    # 64OctetFrames                   :               0 (PKTs)
    # 65-127OctetFrames               :               0 (PKTs)
    # 128-255OctetFrames              :               0 (PKTs)
    # 256-511OctetFrames              :               0 (PKTs)
    # 512-1023OctetFrames             :               0 (PKTs)
    # 1024-1518OctetFrames            :               0 (PKTs)
    # UPFramesDropped                 :               0 (PKTs)
    # DownOctetsTransferred           :     71016502636 (BYTEs)
    # DownTotalFrame                  :       572736211 (PKTs)
    # DownUnicastFrames               :       572518682 (PKTs)
    # DownBroadcastFrames             :          217479 (PKTs)
    # DownMulticastFrames             :              50 (PKTs)
    # DownCRC-32Errors                :               0 (PKTs)
    # DownUndersizeFrames             :               0 (PKTs)
    # DownOversizeFrames              :               0 (PKTs)
    # DownCollisions                  :               0 (PKTs)
    # DownFramesDropped               :               0 (PKTs)
    # UPErrorBIP8                     :               0 (PKTs)
    # DownErrorBIP8                   :               0 (PKTs)
    # UPSpeed                         :            0.00 (Mbps)
    # DownSpeed                       :            0.00 (Mbps)
    # Optical module type             :              20 (Km)
    # Temperature                     :           46.83 ('C)
    # Power(Voltage)                  :            3.34 (V)
    # Bias current                    :           16.65 (mA)
    # Tx_power                        :            2.99 (dbm)
    # Rx_power                        :          -13.14 (dbm)
    # OLT_Rx_power                    :          -14.32 (dbm)

    validate_type('strValue', strValue, str)

    ret = { }

    exp = re.compile('(.+):(.+)\((.+)\)')
    for line in strValue.splitlines():
        match = exp.match(line)
        if match:
            key, value, unit = match.groups()
            ret[key.strip()] = (value.strip(), unit.strip())

    return ret

def extract_bandwidth_profile(strValue):
    """提取show bandwidth-profile的信息

    Args:
        strValue(str): show bandwidth-profile信息
    
    Returns:
        list: 包含onu bandwith profile信息的列表
    """
    # -------- onubandwidth profile, num = 10 --------
    # Id   Name                 upMin  upMax  downMin downMax upFix
    # ------------------------------------------------------------------
    # 2    bwp2                 50000  100000 50000  100000 10000
    # 3    bwp                  10000  10000  10000  10000  10000
    # 8    b_prf_8              0      1000   0      2000   0
    # 51   b_prf_51             0      2000   0      3000   0
    # 326  b_prf_326            0      1000   0      2000   0
    # 392  b_prf_392            0      1000   0      2000   0
    # 592  b_prf_592            0      2000   0      3000   0
    # 623  b_prf_623            0      2000   0      3000   0
    # 667  b_prf_667            0      2000   0      3000   0
    # 720  b_prf_720            0      1000   0      2000   0

    # -------- onubandwidth profile, num = 1 --------
    # Id   Name                 upMin  upMax  downMin downMax upFix
    # ------------------------------------------------------------------
    # 3    bwp                  10000  10000  10000  10000  10000
    validate_type('strValue', strValue, str)

    summaryRegex = re.compile('-+\s+onubandwidth\sprofile,\snum\s+=\s+(\d+)\s-+')

    titlesRegex = re.compile('(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s*')

    itemsRegex = re.compile('(\d+)\s+([\w\d]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*')

    ret = [ ]
    titles = None
    count = None
    for line in strValue.splitlines():

        match = titlesre.match(line)
        if itemsre.match(line):
            
            values = match.groups()

            save = { }
            for t, v in zip(titles, values):
                save[t] = value(v)
            
            ret.append(save)
            continue

        match = summaryre.match(line)
        if match:
            assert len(match.groups()) == 1
            count = int(match.groups()[0])
            continue

        match = titlesre.match(line)
        if match:
            titles = match.groups()
            continue

    assert count == len(ret)

    return ret

def extract_onu_bandwidth(strValue):
    """提取show onu bandwidth数据

    Args:
        strValue(str): show onu bandwidth数据
    
    Returns:
        dict: 包含onu bandwitdh信息的字典
    """
    # onu: slot 4 pon 8 onu 1.
    # upMaxband: 1250000.
    # downMaxband: 2500000.
    # upAssureBand: 640.
    # downAssureBand: 640.
    # upFixband: 0.
    # prfId: -1.
    validate_type('strValue', strValue, str)

    ret = { }
    keyValueRegexExp = re.compile('\s*(\w+)\s*:\s*(-?\d+)\s*\.')
    for line in strValue.splitlines():
        match = keyValueRegexExp.match(line)
        if match:
            k, v = match.groups()
            ret[k]=value(v)
    
    return ret

def extract_bandwidth(strValue):
    """提取show bandwidth数据

    Args:
        strValue(str): show bandwidth数据
    
    Returns:
        dict: 包含bandwitdh信息的字典
    """
    validate_type('strValue', strValue, str)

    # BANDWIDTH: UP 20000      DOWN 20000
    regexExp = 'BANDWIDTH:\s*UP\s*(\d+)\s*DOWN\s*(\d+)'
    
    ret = { }

    for line in strValue.splitlines():
        match = regexExp.match(line)
        if match:
            usPir, dsPir = match.group()
            ret['UP'] = value(usPir)
            ret['DOWN'] = value(dsPir)
        
    return ret

def extract_onu_layer3_rate_limit_profile(strValue):
    """提取show onu layer3-ratelimit-profile数据

    Args:
        strValue (str): show onu layer3-ratelimit-profile数据

    Returns:
        list: 包含字典的列表
    """
    # ------Offline onu layer3 rate-limiting info------
    # Wan index: 1.
    # Wan name: 1_INTERNET_B_VID_1000.
    # Up bandwidth profile id: 3.
    # Down bandwidth profile id: 3.

    # Wan index: 2.
    # Wan name: 2_INTERNET_B_VID_1000.
    # Up bandwidth profile id: 65535.
    # Down bandwidth profile id: 65535.
    validate_type('strValue', strValue, str)

    regexExp = re.compile('(.+)\s*:\s*(.+).')

    ret = [ ]
    for line in strValue.splitlines():
        match = regexExp.match(line)
        if match:
            k, v = match.groups()
            k = k.strip()
            v = v.strip()
            if k == 'Wan index':
                ret.append({ })
            
            ret[-1][k] = value(v)
    
    return ret

def extract_service_vlan(strValue):
    """提取show service-vlan数据

    Args:
        strValue (str): show service-vlan数据

    Returns:
        list: 包含字典的列表
    """
    # servicevlan 101 :
    # name : test,   type : data
    # vlan range:  100 ~ 400 #####end.
    # servicevlan 102 :
    # name : sip,   type : voip
    # vlan range: 3990 #####end.
    validate_type('strValue', strValue, str)

    vlanIndexExp = re.compile('servicevlan\s+(\d+)\s+:\s*')
    nameTypeExp = re.compile('name\s+:\s+(.+),\s+type\s+:\s+(.+)\s*')
    svlanExp = re.compile('vlan\s+range:\s+(\d+|\d+\s+~\s+\d+)\s+#####end.')

    ret = [ ]
    for line in strValue.splitlines():
        match = vlanIndexExp.match(line)
        if match:
            ret.append({ })
            ret[-1]['servicevlan'] = value(match.groups()[0].strip())
            continue

        match = nameTypeExp.match(line)
        if match:
            ret[-1]['name'] = value(match.groups()[0].strip())
            ret[-1]['type'] = value(match.groups()[1].strip())
            continue

        match = svlanExp.match(line)
        if match:
            ret[-1]['vlan range'] = value(match.groups()[0].strip())
            continue
    
    return ret

def extract_onu_qinq_classification_profile(strValue):
    """提取show onuqinq-classification-profile数据

    Args:
        strValue (str): show onuqinq-classification-profile数据

    Returns:
        list: 包含字典的列表
    """
    # ------------------QinQ profile [add2000] information------------------
    # Index: 1
    # Type: Source MAC Address        Value: 00 00 00 00 00 00                        Operator: Exist then match
    # ------------------QinQ profile [xx] information------------------
    # Index: 2
    # Type: Source MAC Address        Value: 00 00 00 00 00 00                        Operator: No exist then match
    # Type: Source MAC Address        Value: 00 00 00 00 00 00                        Operator: No exist then match
    # Type: Source MAC Address        Value: 00 00 00 00 00 00                        Operator: No exist then match
    # Type: Source MAC Address        Value: 00 00 00 00 00 00                        Operator: No exist then match
    # Type: Source MAC Address        Value: 00 00 00 00 00 00                        Operator: No exist then match
    # Type: Source MAC Address        Value: 00 00 00 00 00 00                        Operator: No exist then match
    # Type: Source MAC Address        Value: 00 00 00 00 00 00                        Operator: No exist then match
    # Type: Source MAC Address        Value: 00 00 00 00 00 00                        Operator: No exist then match
    validate_type('strValue', strValue, str)
    
    profileNameExp = re.compile('-+.+\[(.+)\].+-+')
    profileIndexExp = re.compile('Index: (\d+)')
    profileFieldValueOpExp = re.compile('Type:\s+(.+)\s+Value:\s+(.+)\s+Operator:\s+(.+)')

    ret = []
    for line in strValue.splitlines():
        match = profileNameExp.match(line)
        if match:
            ret.append({ })
            ret[-1]['name'] = match.groups()[0].strip()
            continue

        match = profileIndexExp.match(line)
        if match:
            ret[-1]['index'] = value(match.groups()[0].strip())
            continue
        
        match = profileFieldValueOpExp.match(line)
        if match:
            f, v, o = match.groups()

            f = type_str_to_int(f.strip())
            v = onu_value_str_to_str(v.strip(), f)
            o = op_str_to_int(o.strip())

            fvoList = ret[-1].get('fieldValueOps', [ ])
            fvoList.append((f, v, o))
            ret[-1]['fieldValueOps'] = fvoList
            continue
    
    return ret

def extract_olt_qinq_domain(strValue):
    """提取show oltqinq-domain <name> / index <index>数据

    Args:
        strValue (str): show oltqinq-domain <name> / index <index>数据

    Returns:
        dict: 包含信息的字典
    """
    # ------------------QinQ domain [4_8_0536626403] information------------------
    # Domain index: 7         Service num: 1

    # Service type: 0         Service ID: 1
    # Service[1] upstream rule:
    # Type[02]    val[00 00 00 00 00 00 00 00]    opt[5]
    # Service[1] downstream rule:
    # Type[02]    val[00 00 00 00 00 00 00 00]    opt[5]
    # Service[1] vlan information:
    # Layer 1: oldvlan[129] oldcos[2] action[2] tpid[0x8100] cos[0] newvlan[1041]
    # Layer 2: oldvlan[0] oldcos[0] action[3] tpid[0x8100] cos[255] newvlan[65535]
    # Layer 3: oldvlan[65535] oldcos[255] action[3] tpid[0x8100] cos[255] newvlan[65535]
    # Layer 4: oldvlan[65535] oldcos[255] action[3] tpid[0x8100] cos[255] newvlan[65535]
    validate_type('strValue', strValue, str)

    qinqNameExp = re.compile('-+.+\[(.+)\].+-+')
    qinqIndexAndSvcIndexExp = re.compile('Domain index:\s*(\d+)\s*Service num:\s*(\d+)\s*')
    serviceTypeAndIDExp = re.compile('Service type:\s*(\d+)\s*Service ID:\s*(\d+)\s*')
    serviceIndexAndRuleExp = re.compile('Service\[(\d+)\] (\w+) rule:')
    typeValueOpExp = re.compile('Type\[(\d+)\]\s+val\[(.+)\]\s+opt\[(\d+)\]')
    serviceVlanInfoExp = re.compile('Service\[(\d+)\] vlan information:')
    layerExp = re.compile('Layer\s*(\d+):\s*oldvlan\[(.+)\]\s*oldcos\[(.+)\]\s*action\[(.+)\]\s*tpid\[(.+)\]\s*cos\[(.+)\]\s*newvlan\[(.+)\]')
    
    # {
    #     'name': 'profile-name',
    #     'index': 'profile-index',
    #     'count': 'service-count',
    #     'services':
    #         [
    #             {
    #                 'no': 'service-no',
    #                 'type': 'service-type',
    #                 'rule': {
    #                     'upstream': [
    #                   
    #                     ],
    #
    #                     'downstream': [
    #                     ]
    #                 }, 
    #                 'vlan': [
    #                     (layerNo, oldvlan, oldcos, action, newtpid, newcos, newvlan),
    #                     (layerNo, oldvlan, oldcos, action, newtpid, newcos, newvlan)
    #                 ]
    #             }
    #         ]
    # }

    ret = { }

    lastKey = None
    for line in strValue.splitlines():
        match = qinqNameExp.match(line)
        if match:
            ret['name'] = value(match.groups()[0])
            continue

        match = qinqIndexAndSvcIndexExp.match(line)
        if match:
            ret['index'] = value(match.groups()[0])
            ret['count'] = value(match.groups()[1])
            ret['services'] = [ ]
            continue

        match = serviceTypeAndIDExp.match(line)
        if match:
            ret['services'].append({ })
            ret['services'][-1]['no'] = value(match.groups()[1])
            ret['services'][-1]['type'] = 'single' if value(match.groups()[0]) == 0 else 'share'
            ret['services'][-1]['rule'] = { }
            ret['services'][-1]['vlan'] = [ ]
            continue

        match = serviceIndexAndRuleExp.match(line)
        if match:
            no = value(match.groups()[0])
            upOrDownStream = value(match.groups()[1])
            assert no == ret['services'][-1]['no']
            ret['services'][-1]['rule'][upOrDownStream] = [ ]
            lastKey = upOrDownStream
            continue

        match = typeValueOpExp.match(line)
        if match:
            typeCode, rawValue, opCode = match.groups()
            intType = value(typeCode)
            strValue = olt_value_str_to_str(rawValue, intType)
            intOp = value(opCode)
            ret['services'][-1]['rule'][lastKey].append((intType, strValue, intOp))
            continue

        match = serviceVlanInfoExp.match(line)
        if match:
            no = value(match.groups()[0])
            assert no == ret['services'][-1]['no']
            continue
        
        match = layerExp.match(line)
        if match:
            layerNo, oldVlan, oldCos, action, newTpid, newCos, newVlan = match.groups()
            if action == '1':
                action = 'add'
            elif action == '2':
                action = 'translation'
            elif action == '3':
                action = 'transparent'
            else:
                raise ValueError('unknown action value: %s' % action)

            ret['services'][-1]['vlan'].append((value(layerNo), value(oldVlan, 65535), value(oldCos, 255), value(action), value(newTpid), value(newCos, 255), value(newVlan, 65535)))
            continue

    return ret

def extract_olt_qinq_domain_bound_info(strValue):
    """提取show oltqinq-domain bound-info信息

    Args:
        strValue (str): show oltqinq-domain bound-info信息

    Returns:
        tuple: 返回(slot, portNo)元组
    """
    validate_type('strValue', strValue, str)

    lines = strValue.splitlines()

    ponBoundInfoExp = re.compile('Pon bound info: slot id: (\d+); pon id: (\d+).')

    for line in lines:
        match = ponBoundInfoExp.match(line)
        if match:
            slot, portNo = match.groups()
            return value(slot), value(portNo)

    assert False, '没有找到绑定信息: %s' % strValue

def extract_system_time(strValue):
    """提取show time命令的信息

    Args:
        strValue (str): show time命令信息

    Returns:
        tuple: date, time的元组。如'2020-11-23', '17:27:45'
    """
    # Now time is:
    # Current Date is 2020-11-23
    # Current Time is 17:27:45
    # System running time is 6 day  21:34:39
    dateExp = re.compile('Current\s+Date\s+is\s+(\d{4,4}-\d{2,2}-\d{2,2})')
    timeExp = re.compile('Current\s+Time\s+is\s+(\d{2,2}:\d{2,2}:\d{2,2})')

    lines = strValue.splitlines()
    date, time = '', ''
    for line in lines:
        match = dateExp.match(line)
        if match:
            date = match.groups()[0]
            continue

        match = timeExp.match(line)
        if match:
            time = match.groups()[0]
            continue
    
    return date.strip(), time.strip()

def extract_pppoe_plus(strValue):
    """提取show pppoe-plus state命令的信息

    Args:
        strValue (str): show pppoe-plus state命令信息

    Returns:
        dict: 包含PPPoE-Plus状态信息的字典
    """
    validate_type('strValue', strValue, str)

    stateExp = re.compile('(.+):(.+)')

    lines = strValue.splitlines()

    ret = { }
    for line in lines:
        match = stateExp.match(line)
        if match:
            k, v = match.groups()
            ret[value(k)] = value(v)
    
    return ret

def extract_ip_address(strValue):
    """抽取show ip address命令的信息

    Args:
        strValue (str): show ip address命令返回的信息
    
    Returns:
        tuple: 返回ip与mask组成的元组
    """
    validate_type('strValue', strValue, str)

    lines = strValue.splitlines()

    ipExpr = re.compile('debugip\s+(\d+\\.\d+\\.\d+\\.\d+)')
    maskExpr = re.compile('mask\s+(\d+\\.\d+\\.\d+\\.\d+)')

    ip, mask = None, None
    for line in lines:
        match = ipExpr.search(line)
        if match:
            ip = value(match.groups()[0])

        match = maskExpr.search(line)
        if match:
            mask = value(match.groups()[0])
    
    if ip == None or mask == None:
        raise RuntimeWarning('未找到IP/MASK信息')

    return (ip, mask)

def extract_acl(strValue):
    """抽取show acl命令的信息

    Args:
        strValue (str): show acl命令返回的信息
    
    Returns:
        list: 返回包含ACL信息的列表
    """
    validate_type('strValue', strValue, str)

    titles = ['No', 'IP', 'Mask', 'Status']

    valueExpr = re.compile('(\d+)\s+(\d+\\.d+\\.d+\\.d+)\s+(\d+\\.d+\\.d+\\.d+)\s+(\w+)')
    lines = strValue.splitlines()

    ret = [ ]
    for line in lines:
        match = valueExpr.match(line)
        if match:
            ret.append({ })
            for t, v in zip(titles, match.groups()):
                ret[value(t)] = value(v)
    
    return ret

def extract_snmp_time(strValue):
    """抽取show snmp-time命令的信息

    Args:
        strValue (str): show snmp-time显示的信息
    
    Returns:
        dict: 包含ip和interval信息的字典
    """
    validate_type('strValue', strValue, str)

    intervalExpr = re.compile('INTERVAL=(\d+)')
    ipExpr = re.compile('Server\s+IP\s+:\s+(\d+\\.\d+\\.\d+\\.\d+)')

    lines = strValue.splitlines()
    
    ip, interval = None, None
    for line in lines:
        match = intervalExpr.search(line)
        if match:
            interval = value(match.groups()[0])

        match = ipExpr.search(line)
        if match:
            ip = value(match.groups()[0])

    if ip == None or interval == None:
        raise RuntimeWarning('未找到IP和Interval信息')

    return { 'ip': ip, 'interval': interval }

def extract_current_alarm(strValue):
    """抽取show alarm current命令的信息

    Args:
        strValue (str): show alarm current显示的信息

    Returns:
        list: 包含信息的字典
    """
    validate_type('strValue', strValue, str)
    # TODO: FIXME: 抽取告警信息没有实现
    titleExpr = re.compile('\s*(Item Description)\s+(Code vOLT)\s+(Object)\s+(Begintime)\s+(Endtime)\s*')
    valueExpr = re.compile('???')

    lines = strValue.splitlines()

    ret = [ ]
    titles = None
    for line in lines:
        match = titleExpr.match(line)
        if match != None:
            titles = match.groups()
        
        match = valueExpr.match(line)
        if match != None:
            values = match.groups()
            ret.append({ })
            for title, value in zip(titles, values):
                ret[-1][title] = value

    return ret


class OLTCLI_AN6K_17:
    """OLTCLI类。通过它，可以对OLT进行操作，就像输入命令行调用一样。

    """

    def __init__(self, olt_dev):
        """OLT构造函数。

        Args:
            olt_dev (Device): OLT设备资源
        """
        self.olt_dev = olt_dev
    
    def del_onu_caps_profile(self, name):
        """删除ONU能力集模板

        Args:
            name (str): ONU能力集名称
        """
        validate_type('name', name, str)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('no onu caps-profile name %s' % name)

    def add_onu_caps_profile(self, name, onutype, pontype, onucapa, lan1g, lan10g, lan25g, lan2_5g, pots):
        """配置ONU能力集

        Args:
            name (str): [description]
            onutype (int]): ONU类型，范围10000-11023。
            pontype (int): PON类型，可取的值如下
                    263:1G EPON
                    807:10G EPON 10G/10G
                    808:10G EPON 1G/10G
                    712:1G GPON
                    813:10 GPON 2.5G/10G
                    650:10GPON 10G/10G
                    824: GPON/XGPON/XGSPON auto 
                    826: 25G PON 25G/25G
            onucapa (int)): ONU类型，0:SFU 1:hgu 2:box mdu 3:card mdu 4:DPU
            lan1g (int): 1G端口对应的端口号
            lan10g (int): 10G端口对应的端口号
            lan25g (int): 25G端口对应的端口号
            lan2_5g (int): 2.5G端口对应的端口号
            pots (int): pots端口号
        """
        validate_type('name', name, str)
        validate_type('onutype', onutype, int)
        validate_type('pontype', pontype, int)
        validate_type('onucapa', onucapa, int)
        validate_type('lan1g', lan1g, int)
        validate_type('lan10g', lan10g, int)
        validate_type('lan25g', lan25g, int)
        validate_type('lan2_5g', lan2_5g, int)
        validate_type('pots', pots, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('onu caps-profile add name %s onutype %s pontype %s onucapa %s lan1g %s lan10g %s lan25g %s lan2.5g %s pots %s end' % (name, onutype, pontype, onucapa, lan1g, lan10g, lan25g, lan2_5g, pots))

    def get_snmp_time(self):
        """获取SNMP时间配置

        Returns:
            dict: 包含时间配置参数的字典。interval，表示时间间隔；ip，表示SNMP对时的IP地址。
        """

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show snmp-time')
        
        return extract_snmp_time(result)

    def set_snmp_time(self, interval, type, ip):
        """设置SNMP相关参数
        
        Args:
            interval(int): SNMP校时间隔
            type(str): IP类型。有ipv4、ipv6、ipv4z、ipv6z和dns
            ip(str): IP地址
        """
        validate_type('interval', interval, int)
        validate_type('type', type, str)
        validate_type('ip', ip, str)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('snmp-time interval %s servip %s %s' % (interval, type, ip))

    def set_time_mode(self, mode, hour, min, ems_hour, ems_min):
        """设置系统时间模式

        Args:
            mode (str): ne、snmp、ntp、sntp、ptp
            hour (str): 时区，如 GMT+5:30、GMT+8
            min (int): 时区分钟
            ems-hour (str): EMS时区, 如 GMT+5:30、GMT+8
            ems-min (int): 时区分钟
        """
        validate_type('mode', mode, str)
        validate_type('hour', hour, str)
        validate_type('min', min, int)
        validate_type('ems_hour', ems_hour, str)
        validate_type('ems_min', ems_min, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('time %s hour %s min %s ems-hour %s ems-min %s' % (mode, hour, min, ems_hour, ems_min))

    def set_time(self, year, month, day, time):
        """设置系统时间

        Args:
            year (int): 年
            month (int): 月
            day (int): 日
            time (str): HH:MM:SS字符串的时间
        """
        validate_type('year', year, int)
        validate_type('month', month, int)
        validate_type('day', day, int)
        validate_type('time', time, str)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('time %s %s %s %s' % (year, month, day, time))

    def set_traffic_suppress(self, slot, rate, type='all'):
        """设置卡的包抑制参数

        Args:
            slot (int): 槽位号
            rate (int): 速率
            type (str, optional): 抑制类型。支持broadcast、multicast、unknown和all。默认'all'。
        """
        validate_type('slot', slot, int)
        validate_type('rate', rate, int)
        validate_type('type', type, str)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('traffic-suppress 1/%s %s value %s' % (slot, type, rate))

    def set_card_auth(self, slot, type):
        """授权指定卡盘

        Args:
            slot (int): 槽位号
            type (str): 卡类型
        """
        validate_type('slot', slot, int)
        validate_type('type', type, str)

        type = self.get_card_type(slot)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('card auth 1/%s %s' % (slot, type))

    def set_card_auto_auth(self):
        """对卡进行自动授权
        """
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('card auto-auth')  

    def get_card_type(self, slot):
        """查询卡的类型

        Args:
            slot (int): 槽位号

        Returns:
            str: 卡的类型
        """
        validate_type('slot', slot, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show card info')
        
        entires = extract_card_info(result)
        for entry in entires:
            if entry['CARD'] == slot:
                if entry['DETECT'] != '---':
                    return entry['DETECT']
                else:
                    break
        
        raise RuntimeWarning('未查询到卡的类型')

    def unset_card_auth(self, slot):
        """取消卡的授权

        Args:
            slot (int): 卡的槽位号
        """
        validate_type('slot', slot, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('card unauth 1/%s' % slot)

    def set_acl(self, ip, mask , status):
        """设置ACL，即允许或者禁止访问的IP网段

        Args:
            ip (str): IP地址
            mask (str): 点分格式的子网掩码
            status (str): enable或disable
        
        Returns:
            int: 返回设置的ID号
        """
        validate_type('ip', ip, str)
        validate_type('mask', mask, str)
        validate_type('status', status, str)

        # 找一个空闲的ID
        id = None
        for entry in self.get_acl():
            if entry['IP'] == '0.0.0.0' and entry['Mask'] == '0.0.0.0' and entry['Status'] == 'disable':
                id = entry['No']

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('acl %s ip %s mask %s %s' % (id, ip, mask, status))

        return id

    def get_acl(self, id = None):
        """获取ACL配置信息

        Args:
            id (int, optional): 指定了ID，就返回指定的，否则返回所有的。

        Returns:
            list或dict: 返回包含{No, IP, Mask, Status}字典的列表，或返回单个字典
        """
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show acl')
        
        if id == None:
            return extract_acl(result)
        else:
            for entry in extract_acl(result):
                if entry['No'] == id:
                    return entry
            
            raise RuntimeWarning('未能找到指定ID的ACL信息')

    def del_static_route(self, hop, ip, mask, metric = None):
        """删除静态路由

        Args:
            hop (str): 下一跳地址
            ip (str, optional): 目的IP
            mask (str或int, optional): 子网掩码，接受点格式的，或者数字长度格式的
            metric (int): 下一跳的metric，默认None，不提供
        """
        validate_type('hop', hop, str)
        validate_type('ip', ip, str)

        if type(mask) != str and type(mask) != int:
            raise RuntimeWarning('只接受点分格式或者长度格式的掩码')


        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            if metric == None:
                conn.run_cmd('no static-route destination-ip  %s mask %s nexthop %s' % (ip, mask, hop)) 
            else:
                conn.run_cmd('no static-route destination-ip  %s mask %s nexthop %s metric %s' % (ip, mask, hop, metric)) 

    def set_static_route(self, hop, ip = '0.0.0.0', mask = '0.0.0.0', metric = 0):
        """配置静态路由

        Args:
            hop (str): 下一跳地址
            ip (str, optional): 目的IP, 默认0.0.0.0
            mask (str或int, optional): 子网掩码，接受点格式的，或者数字长度格式的, 默认0.0.0.0
            metric (int): 下一跳的metric，默认0
        """
        validate_type('hop', hop, str)
        validate_type('ip', ip, str)

        if type(mask) != str and type(mask) != int:
            raise RuntimeWarning('只接受点分格式或者长度格式的掩码')

        validate_type('metric', metric, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('static-route destination-ip  %s mask %s nexthop %s metric %s' % (ip, mask, hop, metric))

    def set_manage_vlan(self, name, svlan, cvlan):
        """设置带内管理VLAN

        Args:
            svlan (int): SVLAN，外层VLAN
            cvlan (int): CVLAN，内层VLAN
        """
        validate_type('name', name, str)
        validate_type('svlan', svlan, int)
        validate_type('cvlan', cvlan, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('manage-vlan %s svlan %s cvlan %s' % (name, svlan, cvlan))

    def set_manage_vlan_ip(self, version, name, ip, mask):
        """设置带内管理IP

        Args:
            version (str): IPv4或IPv6
            name (str): 先前设置的带内管理VLAN名称
            ip (str): IP地址
            mask (int或str): 子网掩码，如，255.255.255.0，或子网掩码长度，24
        """
        validate_type('version', version, str)
        validate_type('name', name, str)
        validate_type('ip', ip, str)
        
        if type(mask) == str:
            mask = len_of_mask(mask)
        if type(mask) == int:
            pass
        else:
            raise RuntimeWarning('mask类型非法，只接受str或int类型')

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('manage-vlan %s %s %s/%s' % (version, name, ip, mask))

    def set_ip_address(self, ip, mask):
        """为OLT设置带外管理IP地址

        Args:
            ip (str): OLT IP地址
            mask (str): OLT 子网掩码
        """
        validate_type('ip', ip, str)
        validate_type('mask', mask, str)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface meth 1')
            try:
                conn.run_cmd('ip address %s mask %s' % (ip, mask))
            except ConnectionResetError as cr:
                logging.getLogger().debug('当调整OLT的管理IP时，会导致连接断开，这是正常的。需要约3秒恢复。')

                # 等待连接恢复
                time.sleep(5)
        
        ipR, maskR = self.get_ip_address()
        if ipR != ip or maskR != mask:
            raise RuntimeWarning('设置带外管理IP地址失败')

    def get_ip_address(self):
        """获取OLT带外管理IP地址

        Returns:
            tuple: (ip, mask)组成的元组
        """
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface meth 1')
            result = conn.run_cmd('show ip address')
        
        return extract_ip_address(result)

    def get_system_time(self):
        """返回OLT上面的系统时间。等同执行show time命令。

        Returns:
            datetime: datetime类型的系统时间
        """
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show time')
        
        date, time = extract_system_time(result)

        return parse('%s %s' % (date, time))

    def get_authorization(self):
        """获取所有授权的ONU。等同于执行show authorization命令。

        Returns:
            列表: 包含ONU授权信息的字典列表
        """
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show authorization')

        return extract_authorization(result)

    def get_onu_position(self, sn):
        """根据ONU SN查询ONU的槽位号和端口号

        Args:
            sn (str): ONU SN号

        Raises:
            RuntimeWarning: 查不到该ONUID对应信息时，抛出异常

        Returns:
            tuple: 返回(slot, port)元组，如果查不到抛出异常
        """
        validate_type('sn', sn, str)
       
        authInfo = self.get_authorization()
        for info in authInfo:
            if info['PhyId'] == sn:
                return info['Slot'], info['Pon']
        
        onuInfo = self.get_discovery()
        for info in onuInfo:
            if info['PhyId'] == sn:
                return info['SLOT'], info['PON']

        logging.getLogger().warning('查不到该ONU(%s)对应的槽位号和端口号，请检查ONU是否发现' % sn)
        logging.getLogger().debug('authorization:\n %s' % authInfo)
        logging.getLogger().debug('discovery:\n %s' % onuInfo)
        raise RuntimeWarning('查不到该ONU(%s)对应的槽位号和端口号，请检查ONU是否发现' % sn)    

    def get_onu_last_online_time(self, sn):
        """获取ONU最近一次上线时间。等同执行show onu last-reg-status-change <onuId>命令。

        Args:
            sn (str): ONU SN

        Returns:
            datetime: 查不到ONUID抛异常。查到了，但是无最后一次上线时间(一般从未上线)，返回None。正常情况下，返回datetime格式的上线时间。
        """
        validate_type('sn', sn, str)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            result = conn.run_cmd('show onu last-reg-status-change %s' % self.get_onu_id(sn))
        
        dictList = extract_last_reg_status_change(result)

        return dictList[0]['LAST_ON_TIME']

    def get_onu_last_offline_time(self, sn):
        """获取ONU最近一次下线时间。等同执行show onu last-reg-status-change <onuId>命令。

        Args:
            sn (str): ONU SN

        Returns:
            datetime: 查不到ONUID抛异常。查到了，但是无最后一次下线时间(一般从未下线)，返回None。正常情况下，返回datetime格式的最近一次的下线时间。
        """
        validate_type('sn', sn, str)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            result = conn.run_cmd('show onu last-reg-status-change %s' % self.get_onu_id(sn))
        
        dictList = extract_last_reg_status_change(result)

        return dictList[0]["LAST_OFF_TIME"]

    def is_onu_online(self, sn):
        """检查ONU是否在线。等同执行命令show authorization，然后检查其中的OST字段是否为up。

        Args:
            sn (str): ONUD SN

        Returns:
            bool: True，在线；False，不在线。
        """
        validate_type('sn', sn, str)

        values = self.get_authorization()

        for value in values:
            if value["PhyId"] == sn:
                if value["OST"] == "up":
                    return True
                elif value["OST"] == "dn":
                    return False
        
        logging.getLogger().warning('查不到该ONU(%s)状态信息，请检查ONU是否进行过授权' % sn)
        raise RuntimeWarning('查不到该ONU(%s)状态信息，请检查ONU是否进行过授权' % sn)

    def reset_onu(self, sn, wait = True):
        """重置ONU。等同执行onu reset <onuId>命令。

        Args:
            sn (str): ONU SN号
            wait (bool, optional): 重置ONU后，等待重新上线。
        """
        validate_type('sn', sn, str)
        validate_type('wait', wait, bool)

        if not self.is_onu_online(sn):
            raise RuntimeWarning('无法重置离线状态下的ONU')

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            conn.run_cmd('onu reset %s' % self.get_onu_id(sn))
        
        def isOffline():
            return not self.is_onu_online(sn)

        wait_for_true(isOffline, 1, 30)

        if wait:
            def isOnline():
                return self.is_onu_online(sn)
            
            wait_for_true(isOnline, 1, 180)

    def reset_all_onu(self, wait = True):
        """重置所有ONU。等同执行onu reset all命令。不同于resetONU，不会验证是否重启和重新上线。

        Args:
            wait (bool, optional): 重置ONU后，等待重新上线。
        """
        validate_type('wait', wait, bool)

        # 获取所有在线的ONU对应的槽位号和端口号，以及下面挂的ONUID
        stats = { }
        for authInfo in self.get_authorization():
            key = (authInfo['Slot'], authInfo['Pon'])
            if key not in stats.keys():
                stats[key] = set()
    
            if authInfo['OST'] == 'up': # 后面只验证重启时在线的ONU，因为有些ONU重启时可能本来就没上线。
                stats[key].add(authInfo['PhyId'])
        
        # 重启这些个ONU
        for slotPort in stats.keys():
            with Connection.get(self.olt_dev) as conn:
                conn.run_cmd('config')
                conn.run_cmd('interface pon 1/%s/%s' % slotPort)
                # onu reset all命令存在bug，使用普通命令替代
                for sn in stats[slotPort]:
                    conn.run_cmd('onu reset %s' % self.get_onu_id(sn))
                

        # 等待下线
        def isOffline():
            ret = True
            for key in stats.keys():
                for sn in stats[key]:
                    ret = ret and not self.is_onu_online(sn)
            return ret
        
        wait_for_true(isOffline, 1, 30)

        if wait:
            # 等待上线
            def isOnline():
                ret = True
                for key in stats.keys():
                    for sn in stats[key]:
                        ret = ret and self.is_onu_online(sn)
                return ret
            
            wait_for_true(isOnline, 1, 180)

    def clear_whitelist(self):
        """清空所有授权
        """
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            for wlMode in [ WhitelistMode.phyid, WhitelistMode.logid, WhitelistMode.password ]:
                onuInfos = self.get_whitelist(wlMode)
                for onuInfo in onuInfos:
                    if wlMode in [ WhitelistMode.phyid, WhitelistMode.phyid_psw ]:
                        conn.run_cmd('no whitelist phy-id %s %s %s' % (onuInfo['Slot'], onuInfo['Pon'], onuInfo['Phy-ID']))
                    
                    if wlMode in [ WhitelistMode.logid, WhitelistMode.logid_psw ]:
                        conn.run_cmd('no whitelist logic-id %s %s %s' % (onuInfo['Slot'], onuInfo['Pon'], onuInfo['Logic-Id']))                       

                    if wlMode in [ wlMode.password ]:
                        conn.run_cmd('no whitelist password %s %s %s' % (onuInfo['Slot'], onuInfo['Pon'], onuInfo['Phy-Pwd']))

        # 验证
        for wlMode in [ WhitelistMode.phyid, WhitelistMode.logid, WhitelistMode.password ]:
            onuInfos = self.get_whitelist(wlMode)
            if len(onuInfos) != 0:
                raise RuntimeWarning('%s的白名单没有清理干净' % (get_whitelist_query_str(wlMode)))

    def clear_pon_whitelist(self, slot, port):
        """清空指定的槽位号和端口号下的所有类型的ONU授权列表。等同于执行no whitelist all。
        
        Args:
            slot (int): 槽位号
            port (init): 端口号
        """
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % (slot, port))
            conn.run_cmd('no whitelist %s' % 'all')

        for wlMode in [ WhitelistMode.phyid, WhitelistMode.logid, WhitelistMode.password ]:
            whiteList = self.get_pon_whitelist(slot, port, wlMode)
            if len(whiteList) != 0:
                raise RuntimeError('清空白名单(%s)失败' % wlMode)

    def get_pon_whitelist(self, slot, port, wlMode):
        """获取指定槽位号和端口下的指定类型的白名单列表。等同于执行show whitelist命令。

        Args:
            slot (int): 槽位号
            port (int): 端口号
            wlMode (WhitelistMode): 白名单类型

        Returns:
            list: 包含授权信息的列表
        """
        validate_type('slot', slot, int)
        validate_type('port', port, int)
        validate_type('wlMode', wlMode, WhitelistMode)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % (slot, port))
            result = conn.run_cmd('show whitelist %s' % get_whitelist_query_str(wlMode))
        
        return extract_whitelist(result)

    def get_whitelist(self, wlMode):
        """读取白名单列表。等同于执行show whitelist命令。

        Args:
            wlMode (WhitelistMode): 指定要获取哪种白名单类型的列表。

        Returns:
            list: 包含授权字典信息的列表
        """
        validate_type('wlMode', wlMode, WhitelistMode)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show whitelist %s' % get_whitelist_query_str(wlMode))

        return extract_whitelist(result)

    def is_in_whitelist(self, wlMode, id):
        """检查ONU是否在对应白名单列表中。

        Args:
            wlMode (WhitelistMode): 要在哪个白名单列表中检查
            id (str): ONU的phyId、logId或passwd

        Returns:
            bool: True，在白名单列表中；False，不在白名单列表中
        """
        validate_type('wlMode', wlMode, WhitelistMode)
        validate_type('sn', id, str)

        id = value(id)

        onuInfos = self.get_whitelist(wlMode)
        for onuInfo in onuInfos:
            if wlMode in [ WhitelistMode.phyid, WhitelistMode.phyid_psw ]:
                if onuInfo['Phy-ID'] == id:
                    return True

            if wlMode in [ WhitelistMode.logid, WhitelistMode.logid_psw ]:
                if onuInfo['Logic-Id'] == id:
                    return True

            if wlMode in  [ WhitelistMode.password ]:
                if onuInfo['Phy-Pwd'] == id:
                    return True

        return False

    def is_onu_in_whitelist(self, id):
        """验证ONU是否在白名单中

        Args:
            id (str): ONU的phyId、logId或passwd
        """
        for wlMode in WhitelistMode:
            if self.is_in_whitelist(wlMode, id):
                return True
        
        return False

    def add_whitelist(self, wlMode, sn, onuId=None):
        """将指定的sn号的ONU增加到指定白名单中。支持三种认证方式: sn、sn/pwd, pwd。增加白名单所需的信息自动去查ONU上报的信息。
        
        Args:
            wlMode (WhitelistMode): 要增加到哪个白名单
            sn (str): ONU的SN，加白名单所需的信息会自动去查
            onuid (int or None): 指定onuid，不指定自动分配。默认None，自动分配。
        """

        # 物理授权
        # phy-id / phy-id + psw 
        # 逻辑授权
        # log-id / log-id + psw
        # 密码授权
        # psw
        validate_type('wlMode', wlMode, WhitelistMode)
        validate_type('sn', sn, str)
        if onuId != None:
            validate_type('onuid', onuId, int)


        # 配置所需的LogicId/Pwd, PhyId/Phy
        onuDetailInfo = None
        onuInfos = self.get_discovery()
        for onuInfo in onuInfos:
            if onuInfo['PhyId'] == sn:
                onuDetailInfo = onuInfo
                break
        
        if onuDetailInfo == None:
            raise RuntimeWarning('未查到该ONU信息，无法进行有效配置')


        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            if wlMode == WhitelistMode.phyid:
                if onuId == None:
                    conn.run_cmd('whitelist add phy-id %s' % (onuDetailInfo['PhyId']))
                else:
                    conn.run_cmd('whitelist add phy-id %s onuid %s' % (onuDetailInfo['PhyId'], onuId))

                if not self.is_in_whitelist(wlMode, onuDetailInfo['PhyId']):
                    raise RuntimeWarning("白名单添加失败")
            
            if wlMode == WhitelistMode.phyid_psw:
                if onuId == None:
                    conn.run_cmd('whitelist add phy-id %s checkcode %s' % (onuDetailInfo['PhyId'], onuDetailInfo['PhyPwd']))
                else:
                    conn.run_cmd('whitelist add phy-id %s checkcode %s onuid %s' % (onuDetailInfo['PhyId'], onuDetailInfo['PhyPwd'], onuId))

                if not self.is_in_whitelist(wlMode, onuDetailInfo['PhyId']):
                    raise RuntimeWarning("白名单添加失败")
            
            if wlMode == WhitelistMode.logid:
                if onuId == None:
                    conn.run_cmd('whitelist add logic-id %s' % (onuDetailInfo['LogicId']))
                else:
                    conn.run_cmd('whitelist add logic-id %s onuid %s' % (onuDetailInfo['LogicId'], onuId))

                if not self.is_in_whitelist(wlMode, onuDetailInfo['LogicId']):
                    raise RuntimeWarning("白名单添加失败")

            if wlMode == WhitelistMode.logid_psw:
                if onuId == None:
                    conn.run_cmd('whitelist add logic-id %s checkcode %s' % (onuDetailInfo['LogicId'], onuDetailInfo['LogicPwd']))
                else:
                    conn.run_cmd('whitelist add logic-id %s checkcode %s onuid %s' % (onuDetailInfo['LogicId'], onuDetailInfo['LogicPwd'], onuId))

                if not self.is_in_whitelist(wlMode, onuDetailInfo['LogicId']):
                    raise RuntimeWarning("白名单添加失败")

            if wlMode == WhitelistMode.password:
                if onuId == None:
                    conn.run_cmd('whitelist add password %s' % (onuDetailInfo['PhyPwd']))
                else:
                    conn.run_cmd('whitelist add password %s onuid %s' % (onuDetailInfo['PhyPwd'], onuId))

                if not self.is_in_whitelist(wlMode, onuDetailInfo['PhyPwd']):
                    raise RuntimeWarning("白名单添加失败")   

    def del_whitelist(self, wlMode, id):
        """从指定白名单里删除指定的ONU

        Args:
            wlMode (Whitelist): 要从哪个白名单里面删除
            id (str): ONU的phyId、logId或passwd
        """
        validate_type('wlMode', wlMode, WhitelistMode)
        validate_type('sn', id, str)

        if not self.is_in_whitelist(wlMode, id):
            return
        
        onuInfos = self.get_whitelist(wlMode)
        with Connection.get(self.olt_dev) as conn:

            conn.run_cmd('config')
            
            for onuInfo in onuInfos:
                if wlMode in [ WhitelistMode.phyid, WhitelistMode.phyid_psw ] and id == onuInfo['Phy-ID']:
                    conn.run_cmd('no whitelist phy-id %s %s %s' % (onuInfo['Slot'], onuInfo['Pon'], id))
                    
                if wlMode in [ WhitelistMode.logid, WhitelistMode.logid_psw ] and id == onuInfo['Logic-Id']:
                    conn.run_cmd('no whitelist logic-id %s %s %s' % (onuInfo['Slot'], onuInfo['Pon'], onuInfo['Logic-Id']))                       

                if wlMode in [ WhitelistMode.password ] and id == onuInfo['Phy-Pwd']:
                    conn.run_cmd('no whitelist password %s %s %s' % (onuInfo['Slot'], onuInfo['Pon'], onuInfo['Phy-Pwd']))

        if self.is_in_whitelist(wlMode, id):
            raise RuntimeWarning('删除指定白名单中的ONU失败')

    def del_from_whitelist(self, id):
        """将指定的ONU从白名单中移除

        Args:
            id (str): ONU的phyId、logId或passwd
        """
        for wlMode in WhitelistMode:
            self.del_whitelist(wlMode, id)

    def get_auto_discover(self, slot, port):
        """获取ONU自动发现设置。等同于执行show onu auto-discover。

        Args:
            slot (int): 槽位号
            port (int): 端口号

        Returns:
           list : 返回(slot, portNo, status, agingTime)元组组成的列表
        """
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show onu auto-discover 1/%s/%s' % (slot, port))

        return extract_auto_discover(result)

    def get_pon_auto_discover(self, slot, port):
        """获取指定槽位号和端口下的ONU自动发现设置。等同于执行show onu auto-discover。

        Args:
            slot (int): 槽位号
            portNo (int): 端口号

        Returns:
            tuple: (status, agingTime)元组
        """
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % (slot, port))
            result = conn.run_cmd('show onu auto-discover')

        return extract_pon_auto_discover(result)

    def set_auto_discover(self, where, status, agingTime):
        """设置ONU自动发现时间。等同于执行onu auto-discover命令。

        Args:
            where (str): <frameid/slotid/portid>或者'all'
            status (str): enable或者disable
            agingTime (int): 发现时间
        """
        validate_type('where', where, str)
        validate_type('status', status, str)
        validate_type('agingTime', agingTime, int)
        validate_int_range(agingTime, 0, 3600)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('onu auto-discover %s %s %s' % (where, status, agingTime))

    def set_pon_auto_discover(self, slot, port, status, agingTime):
        """设置指定槽位号、端口号下的ONU自动发现设置。等同于执行onu auto-discover命令。

        Args:
            slot (int): 槽位号
            port (int): 端口号
            status (str): enable或者disable
            agingTime (int): 发现时间
        """
        validate_type('slot', slot, int)
        validate_type('port', port, int)
        validate_type('status', status, str)
        validate_type('agingTime', agingTime, int)
        validate_int_range('agingTime', 0, 3600)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % (slot, port))
            conn.run_cmd('onu auto-discover %s %s' % (status, agingTime))

    def get_discovery(self):
        """查询自动发现的ONU。等同于执行show discovery命令。

        Returns:
            list: 返回自动发现的ONU信息列表
        """

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show discovery')

        ret = extract_discovery(result)

        return ret

    def get_pon_discovered(self, slot, port):
        """查询自动发现的ONU。等同于执行show onu discovered命令。
        
        Args:
            slot (int): 槽位号
            port (int): 端口号
        
        Returns:
            list: 返回自动发现的ONU信息列表
        """
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % (slot, port))
            result = conn.run_cmd('show onu discovered')

        ret = extract_discovery(result)

        return ret

    def get_manage_vlan(self, name = None):
        """获取所有管理VLAN。等同于执行show manage-vlan all命令

        Args:
            name (str, optional): 要查询的管理VLAN名称。如果为None，则返回所有管理VLAN。默认为None。

        Returns:
            list或dict: 包含管理VLAN信息字典的列表，或指定VLAN信息的字典。
        """
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show manage-vlan all')

        vlanList = extract_manage_vlan(result)
        if name == None:
            return vlanList
        else:
            for vlan in vlanList:
                if vlan['Manage name'] == name:
                    return vlan
            raise RuntimeWarning('未找到%s名称的管理VLAN信息' % name)

    def set_auth_mode(self, slot, port, mode):
        """设置指定端口的授权模式。等同于执行port authentication-mode命令。

        Args:
            slot (int): 槽位号
            port (int): 端口号
            mode (AuthMode): 授权模式
        """
        validate_type('slot', slot, int)
        validate_type('port', port, int)
        validate_type('mode', mode, AuthMode)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('port authentication-mode 1/%s/%s mode %s' % (slot, port, mode.value))
        
        assert self.get_auth_mode(slot, port) == mode
    
    def get_auth_mode(self, slot = None, port = None):
        """获取指定端口的授权模式。等同于执行show port authentication-mode命令

        Args:
            slot (int, optional): 槽位号。默认None，获取所有端口的授权信息。
            port (int, optional): 端口号。默认None，获取所有端口的授权信息。

        Returns:
            dict或AuthMode: 获取所有授权信息时，返回(slot, port)为键，AuthMode为值的字典。获取个别端口端口的授权模式时，返回AuthMode。 
        """
        if (slot, port) != (None, None):
            validate_type('slot', slot, int)
            validate_type('port', port, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            if (slot, port) == (None, None):
                result = conn.run_cmd('show port authentication-mode all')
                return extract_port_authentication_mode(result)
            else: 
                result = conn.run_cmd('show port authentication-mode select 1/%s/%s' % (slot, port))
                dictRet = extract_port_authentication_mode(result)
                return dictRet[slot, port]

    def set_dhcp_option(self, option, enable=True):
        """设置DHCP选项开关。等同于执行dhcp option18/option37/option82/patch命令。

        Args:
            option (DhcpOption): dhcp option选项
            enable (bool, optional): 是否打开。默认为True，打开。
        """
        validate_type('option', option, DhcpOption)
        validate_type('enable', enable, bool)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('dhcp %s %s' % (option.value, bool_to_str(enable)))

    def get_dhcp_option(self):
        """获取dhcp选项开关状态。等同于执行show dhcp state命令。

        Return:
            dict, 包含dhcp状态信息的字典。
        """
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show dhcp state')

        ret = extract_dhcp_state(result)

        return ret

    def set_pppoe_plus(self, enable=True):
        """设置PPPoE+选项状态。等同于执行pppoe-plus enable/disable命令。

        Args:
            enable (bool, optional): 默认为True，打开PPPoE+开关。
        """
        validate_type('enable', enable, bool)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('pppoe-plus %s' % bool_to_str(enable))

    def get_pppoe_plus(self):
        """获取PPPoE+选项状态。等同于执行show pppoe-plus state命令。

        return:
            bool: True使能， False未使能。
        """
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show pppoe-plus state')
        
        ret = extract_pppoe_plus(result)
    
        return str_to_bool(ret['PPPoE+'])

    def get_onu_sn(self, slot, port, onuId):
        """给定ONUID，查找其SN号。等同于执行show authorization，从里面查找对应关系。

        Args:
            slot(int): 槽位号
            port(int): 端口号
            onuId (int): ONU ID
        
        Return:
            str: 找到，返回ONU SN；没找到，返回None。
        """
        validate_type('onuId', onuId, int)

        authList = self.get_authorization()
        for info in authList:
            if info['Onu'] == onuId and info['Slot'] == slot and info['Pon'] == port:
                return info['PhyId']
        
        return None

    def get_onu_id(self, sn):
        """给定SN，查找ONUID。等同于执行show authorization，从里面查找对应关系。

        Args:
            sn (str): onu sn
        
        Return:
            int : 找到返回ONU ID, 没找到，返回None。
        """
        validate_type('sn', sn, str)

        authList = self.get_authorization()
        for info in authList:
            if info['PhyId'] == sn:
                return info['Onu']
        
        return None

    def set_onu_port_vlan_tls(self, sn, eth, index, tls):
        """设置ONU Port Vlan TLS特性

        Args:
            sn (str): ONU SN
            eth (int): ONU 端口号
            index (int): ONU Service 索引号
            tls (bool): 是否启用tls，True，启用，False，不启用
        """
        validate_type('sn', sn, str)
        validate_type('eth', eth, int)
        validate_type('index', index, int)
        validate_type('tls', tls, bool)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            conn.run_cmd('onu port vlan %s eth %s service %s tls %s' % (self.get_onu_id(sn), eth, index, bool_to_str(tls)))

    def get_onu_port_vlan(self, sn):
        """读取ONU的Port Vlan业务设置。等同于执行命令show onu port vlan。

        Args:
            sn (str): 要显示的ONU的SN
        
        Return:
            list : 元组列表。
        """
        validate_type('sn', sn, str)
        
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            result = conn.run_cmd('show onu port vlan %s' % self.get_onu_id(sn))
        
        ret = extract_onu_port_vlan(result)

        return ret  

    def get_onu_port_status(self, sn):
        """获取ONU端口状态。等同于执行命令show onu port status。

        Args:
            sn (str): ONU SN

        Returns:
            list: 端口状态列表
        """
        validate_type('sn', sn, str)

        if not self.is_onu_online(sn):
            raise RuntimeWarning('无法查询离线状态下的ONU端口状态')

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('terminal length 0')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            result = conn.run_cmd('show onu port status %s' % self.get_onu_id(sn))
        
        ret = extract_onu_port_status(result)

        return ret

    def clear_onu_port_vlan(self, sn, eth='all'):
        """清理指定ONUID下的Port Vlan设置。等同于执行no onu port vlan命令。

        Args:
            sn (str): ONU SN
            eth (str或int): 要清理的网口
        """
        validate_type('sn', sn, str)
        if eth != 'all':
            validate_type('eth', eth, int)
        
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            if eth == 'all':
                if not self.is_onu_online(sn):
                    raise RuntimeWarning('ONU不在线，无法查询其端口数')
                ethCount = len(self.get_onu_port_status(sn)['PORT'])
                for eth in range(1, ethCount + 1):
                    conn.run_cmd('no onu port vlan %s eth %s' % (self.get_onu_id(sn), eth))
            else:
                conn.run_cmd('no onu port vlan %s eth %s' % (self.get_onu_id(sn), eth))

    def get_onu_port_vlan_service_count(self, sn, eth):
        """获取ONU Port VLAN业务个数。

        Args:
            sn (str): ONU SN
            eth (int): 要获取的ONU对应的网口
        
        Returns:
            int: 返回业务个数
        """
        validate_type('sn', sn, str)
        validate_type('eth', eth, int)


        portVlanList = self.get_onu_port_vlan(sn)

        def filterEth(item):

            if item['PORT'] == eth:
                return True

            return False
        
        i = 0
        for _ in filter(filterEth, portVlanList):
            i = i + 1
        return i

    def set_onu_port_vlan_service_count(self, sn, eth, count):
        """设置ONU Port VLAN业务个数。等同于执行onu port vlan命令。

        Args:
            sn (str): ONU SN
            eth (int): 要设置的ONU对应的网口
            count (int): 要设置的业务个数
        """
        validate_type('sn', sn, str)
        validate_type('eth', eth , int)
        validate_type('count', count, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            conn.run_cmd('onu port vlan %s eth %s service count %s' % (self.get_onu_id(sn), eth, count))

    def set_onu_port_vlan_service_type(self, sn, eth, index, type):
        """"设置ONU Port VLAN业务类型。等同于执行onu port vlan命令。

        Args:
            sn (str): ONU SN
            eth (int): 网口的索引值，从1开始。
            index (int): 业务的索引值，从1开始。
            type (str): unicast，表示单播; multicast，表示多播。
        """
        validate_type('sn', sn, str)
        validate_type('eth', eth, int)
        validate_type('index', index, int)
        validate_type('type', type, str)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            conn.run_cmd('onu port vlan %s eth %s service %s type %s' % (self.get_onu_id(sn), eth, index, type))

    def set_onu_port_vlan_service_vlan(self, sn, eth, index, rule):
        """设置ONU Port Vlan业务

        设置方法示例:
            setONUPortVlanServiceVlan('FHTT000aae64', 1, 1, ('tag', 0, 33024, 1000))
            setONUPortVlanServiceVlan('FHTT000aae64', 1, 1, ('transparent', 0, 33024, 1000))
            setONUPortVlanServiceVlan('FHTT000aae64', 1, 1, ('translate', 'enable', 0, 33024, 1000))
            setONUPortVlanServiceVlan('FHTT000aae64', 1, 1, ('translate', 'disable', 0, 33024, 1000))
            setONUPortVlanServiceVlan('FHTT000aae64', 1, 1, ('qinq', 'enable', 0, 33024, 1000, 'qinqClsProfile', 'serviceProfile'))

        Args:
            sn (str): ONU SN
            eth (int): 网口的索引值，从1开始。
            index (int): 业务的索引值，从1开始。
            rule (tuple): LAN业务参数， 以元组的方式提供。
        """
        validate_type('sn', sn, str)
        validate_type('eth', eth, int)
        validate_type('index', index, int)
        validate_type('rule', rule, tuple)

        # pvlan格式化模板
        pvlanFormat = '%s priority %s vid %s'
        # tag格式化模板
        tagFormat = '%s priority %s tpid %s vid %s'
        # translate格式化模板
        translateEnableFormat = '%s %s priority %s tpid %s vid %s'
        translateDisableFormat = '%s %s'
        # transparent格式化模板
        transparentFormat = '%s priority %s tpid %s vid %s'
        # qinq格式化模板
        qinqEnableFormat = '%s %s priority %s tpid %s vid %s %s %s'
        qinqDisableFormat = '%s %s'

        mode = rule[0]
        if mode == 'pvlan':
            ruleString = pvlanFormat % rule
        elif mode == 'tag':
            ruleString = tagFormat % rule
        elif mode == 'translate':
            if rule[1] == 'enable':
                ruleString = translateEnableFormat % rule
            else:
                assert rule[1] == 'disable'
                ruleString = translateDisableFormat % rule
        elif mode == 'transparent':
            ruleString = transparentFormat % rule
        elif mode == 'qinq':
            if rule[1] == 'enable':
                ruleString = qinqEnableFormat % rule
            else:
                assert rule[1] == 'disable'
                ruleString = qinqDisableFormat % rule
        else:
            raise ValueError('未知VLAN设置参数：%s' % str(rule))

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            conn.run_cmd('onu port vlan %s eth %s service %s %s' % (self.get_onu_id(sn), eth, index, ruleString))
 
    def del_onu_port_vlan_service(self, sn, eth, index):
        """删除指定ONU下面指定网口的指定业务

        Args:
            sn (str): ONU SN
            eth (int): 要删除的网口
            index (int): 要删除的业务ID
        """
        validate_type('sn', sn, str)
        validate_type('eth', eth, int)
        validate_type('index', index, int)
        
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            conn.run_cmd('no onu port vlan %s eth %s service %s' % (self.get_onu_id(sn), eth, index))

    def set_onu_port_vlan_service_classification(self, sn, eth, index, ruleList):
        """设置ONU端口业务区分规则

        Args:
            sn (str): ONU SN
            eth (int): 网口的索引值，从1开始。
            index (int): 业务的索引值，从1开始。
            ruleList(list): 规则清单, (类型，操作，值，方向)元组组成的列表
        """
        validate_type('sn', sn, str)
        validate_type('eth', eth, int)
        validate_type('index', index, int)
        validate_type('ruleList', ruleList, list)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            for rule in ruleList:
                type_, op_, value_, direction_ = rule
                cmd2run = 'onu port vlan %s eth %s service %s %s %s %s %s' % (self.get_onu_id(sn), eth, index, direction_.value, type_.value, value_, op_.value)
                conn.run_cmd(cmd2run)

    def set_igmp_vlan(self, vlan):
        """设置组播VLAN。等同于执行igmp vlan命令

        Args:
            vlan (int或str): VLAN ID。str类型的会自动转换为int类型。
        """
        if type(vlan) == str:
            vlan = value(vlan)
        validate_type('vlan', vlan, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('igmp')
            conn.run_cmd('igmp vlan %s' % vlan)

    def get_igmp_vlan(self, vlan):
        """获取组播VLAN设置。等同于执行命令show igmp vlan。

        Args:
            vlan (int或str): 要查询的组播VLAN ID。

        Returns:
            dict: 组播VLAN信息字典。
        """
        if type(vlan) == str:
            vlan = value(vlan)
        
        validate_type('vlan', vlan, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('igmp')
            result = conn.run_cmd('show igmp vlan %s' % vlan)

        return extract_igmp_vlan(result)

    def set_igmp_mode(self, mode):
        """设置组播模式。等同于执行命令igmp mode。

        Args:
            mode (IGMPMode或str): 要设置的组播模式。str类型的参数会自动转换为IGMPMode类型。
        """
        #做一次转换
        if type(mode) == str:
            mode = IGMPMode(mode)
        
        validate_type('mode', mode, IGMPMode)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('igmp')
            conn.run_cmd('igmp mode %s' % mode.value)
        
        ret = self.get_igmp_mode()
        try:
            if ret['IGMP/MLD Mode'] != mode.value:
                raise RuntimeWarning('设置%s组播模式失败' % mode.value)
        except KeyError as ke:
            logging.getLogger().error(ret)
            raise RuntimeWarning('验证组播模式设置是否成功时，出现异常，无法IGMP/MLD Mode项')

    def get_igmp_mode(self):
        """获取组播模式信息。等同于执行命令show igmp mode。

        Return:
            dict: 包含组播模式信息的字典。
        """

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('igmp')
            result = conn.run_cmd('show igmp mode')
        
        ret = extract_igmp_mode_info(result)
        return ret

    def set_port_vlan(self, vlan, tag=None, slot=None, port=None):
        """设置上联口端口VLAN。如果已经设置了某个VLAN，需要先删除再设置，否则会失败。等同于执行port vlan命令。

        Args:
            vlan (str或int): 要设置的VLAN范围。如，1000，或1000 to 2000.
            tag (str): tag，数据出去时不剥离标签; untag，数据出去时剥离标签。
            slot (int): 要设置的槽位号。如，9。不指定，则设置所有端口
            port (str): 要设置的端口号。如，'2'，或'2, 3'。不指定，则设置所有端口
        """
        vlan = str(vlan)

        validate_type('vlan', vlan, str)
        validate_type('tag', tag, str)
        validate_type('slot', slot, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            if slot == None and port == None and tag == None:
                conn.run_cmd('port vlan %s allslot' % (vlan))
            else:
                conn.run_cmd('port vlan %s %s 1/%s %s' % (vlan, tag, slot, port))        

    def get_port_vlan(self, slot, port):
        """查询指定槽位和端口的Port VLAN信息。等同于执行show port vlan命令。

        Args:
            slot (int): 要查的槽位号。
            port (int): 要查的端口号。
        
        Returns:
            list: 包含VLAN信息的元组列表。
        """
        validate_type('slot', slot, int)
        validate_type('port', port, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show port vlan 1/%s/%s' % (slot, port))
        
        return extract_port_vlan(result)
    
    def del_port_vlan(self, vlan, slot, port):
        """删除上联口端口VLAN。等同于执行no port vlan命令。

        Args:
            vlan (str): 要删除的VLAN范围。如，1000，或1000 to 2000.
            slot (int): 要设置的槽位号。如，9
            port (str): 要设置的端口号。如，'2'，或'2, 3'。
        """

        validate_type('vlan', vlan, str)
        validate_type('slot', slot, int)


        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            try:
                conn.run_cmd('no port vlan %s 1/%s %s' % (vlan, slot, port))
            except RuntimeWarning as rw:
                logging.getLogger().debug('不存在该Port VLAN配置')

    def set_onu_wan_cfg(self, **kargs):
        """配置ONU WAN设置。等同于执行onu wan-cfg命令。

        Args:
            onuid (int): 要设置的ONU ID
            index (int): 要设置的wan cfg的index
            mode (WanMode): 要设置的wan模式
            type (WanType): 要设置的wan类型
            wvid (int): WAN VLAN ID
            wcos (int): WAN COS
            nat (str): 是否使能NAT，enable使能，disable去使能
            qos (str): 是否使能QoS，enable使能，disable去使能
            vlanmode (str, optional): 支持tag和transparent
            tvlan (str, optional): 是否翻译VLAN，enable翻译，disable不翻译
            tvid (int, optional): TVLAN ID
            tcos (int, optional): TVLAN COS
            qinq (str, optional): 是否使能QinQ, enable使能，disable去使能
            stpid (int, optional): QinQ设置中的SVLAN的TPID
            svlan (int, optional): QinQ设置中的SVLAN ID
            scos (int, optional): QinQ设置中的SVLAN的COS
            dsp (DSPMode): DSP模式
            remoteid (str, optional): DSP模式为dhcp-remoteid时，指定的remoteid
            ip (str, optional): DSP模式为static时，指定的ip地址
            mask (str, optional):  DSP模式为static时，指定的mask
            gate (str, optional): DSP模式为static时，指定的gateway
            master (str, optional): DSP模式为static时，指定的主DNS
            slave (str, optional): DSP模式为static时，指定的从DNS
            proxy (str, optional): PPPoE模式下，是否使能代理模式，enable使能，disable去使能
            username (str, optional): PPPoE模式下，鉴权的账号名
            password (str, optional): PPPoE模式下，鉴权的密码
            servername (str, optional): PPPoE模式下，PPPoE服务名
            pppoemode (PPPoEMode, optional): PPPoE模式下，PPPoE模式，支持auto/payload/manual三种
            active (str, optional): 是否active，enable使能，disable去使能
            servicetype (int, optional): 业务类型
            upnp (str, optional): 是否使能uPnP功能，enable使能，disable去使能
            fe (list, optional): 要绑定的网口。字符串列表形式提供，如，['fe1', 'fe2']
            ssid (str, optional): 要绑定的SSID。字符串列表形式提供，如，['ssid1', 'ssid2']
        """
        validate_key(kargs, 'onuId', int)
        validate_key(kargs, 'index', int)
        validate_key(kargs, 'mode', WanMode)
        validate_key(kargs, 'type', WanType)
        validate_key(kargs, 'wvid', int)
        validate_key(kargs, 'wcos', int)
        validate_key(kargs, 'nat', str)
        validate_key(kargs, 'qos', str)

        wanCfgCMDPart1 = 'onu wan-cfg %s index %s mode %s type %s %s %s nat %s qos %s ' % \
            (
                kargs['onuId'],
                kargs['index'],
                kargs['mode'].value,
                kargs['type'].value,
                kargs['wvid'],
                kargs['wcos'],
                kargs['nat'],
                kargs['qos']
            )
        
        wanCfgCMDPart2 = ' '
        if 'vlanmode' in kargs.keys():
            validate_key(kargs, 'vlanmode', str)
            validate_key(kargs, 'tvlan', str)
            validate_key(kargs, 'tvid', int)
            validate_key(kargs, 'tcos', int)

            wanCfgCMDPart2 = 'vlanmode %s tvlan %s %s %s ' % \
                (
                    kargs['vlanmode'],
                    kargs['tvlan'],
                    kargs['tvid'],
                    kargs['tcos']
                )

        if 'qinq' in kargs.keys():
            validate_key(kargs, 'qinq', str)
            validate_key(kargs, 'stpid', int)
            validate_key(kargs, 'svlan', int)
            validate_key(kargs, 'scos', int)

            wanCfgCMDPart2 = 'qinq %s %s %s %s ' % \
                (
                    kargs['qinq'],
                    kargs['stpid'],
                    kargs['svlan'],
                    kargs['scos']
                )
        
        wanCfgCMDPart3 = ' '
        validate_key(kargs, 'dsp', DSPMode)
        if kargs['dsp'] == DSPMode.pppoe:
            validate_key(kargs, 'proxy', str)
            validate_key(kargs, 'username', str)
            validate_key(kargs, 'password', str)
            validate_key(kargs, 'servername', str)
            validate_key(kargs, 'pppoemode', PPPoEMode)

            wanCfgCMDPart3 = 'dsp %s proxy %s %s %s %s %s ' % \
                (
                    kargs['dsp'].value,
                    kargs['proxy'],
                    kargs['username'],
                    kargs['password'],
                    kargs['servername'],
                    kargs['pppoemode'].value
                )

        elif kargs['dsp'] == DSPMode.dhcp:
            pass
        elif kargs['dsp'] == DSPMode.dhcp_remoteid:
            validate_key(kargs, 'remoteid', str)

            wanCfgCMDPart3 = 'dsp %s %s ' % \
                (
                    kargs['dsp'].value,
                    kargs['remoteid']
                )

        elif kargs['dsp'] == DSPMode.static:
            validate_key(kargs, 'ip', str)
            validate_key(kargs, 'mask', str)
            validate_key(kargs, 'gate', str)
            validate_key(kargs, 'master', str)
            validate_key(kargs, 'slave', str)

            wanCfgCMDPart3 = 'dsp %s ip %s mask %s gate %s master %s slave %s ' % \
                (
                    kargs['dsp'].value,
                    kargs['ip'],
                    kargs['mask'],
                    kargs['gate'],
                    kargs['master'],
                    kargs['slave']
                )
        else:
            pass
        
        wanCfgCMDPart4 = ' '
        if 'active' in kargs.keys():
            validate_type('active', kargs['active'], str)
            wanCfgCMDPart4 = wanCfgCMDPart4 + 'active %s ' % kargs['active']

        if 'servicetype' in kargs.keys():
            validate_type('servicetype', kargs['servicetype'], int)
            wanCfgCMDPart4 = wanCfgCMDPart4 + 'service-type %s ' % kargs['servicetype']

        if 'upnp' in kargs.keys():
            validate_type('upnp', kargs['upnp'], str)
            wanCfgCMDPart4 = wanCfgCMDPart4 + 'upnp_switch %s ' % kargs['upnp']
        
        if 'fe' in kargs.keys() or 'ssid' in kargs.keys():

            if 'fe' not in kargs.keys():
                kargs['fe'] = [ ]
            
            if 'ssid' not in kargs.keys():
                kargs['ssid'] = [ ]

            wanCfgCMDPart4 = 'entries %s %s %s' % (
                len(kargs['fe']) + len(kargs['ssid']),
                list_to_str(kargs['fe']),
                list_to_str(kargs['ssid']),
            )
        
        cmd2Run = wanCfgCMDPart1 + wanCfgCMDPart2 + wanCfgCMDPart3 + wanCfgCMDPart4

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(kargs['onuId']))
            conn.run_cmd(cmd2Run)

    def get_onu_wan_cfg(self, sn, index):
        """读取指定ONU ID和WAN INDEX的配置。等同于执行命令show onu wan-cfg。

        Args:
            sn (str): ONU SN
            index (int): 要获取的WAN index

        Returns:
            dict: 包含配置信息的字典。字典的键名参考setONUWanCfg
        """
        validate_type('sn', sn, str)
        validate_type('index', index, int)

        with Connection.get(self.olt_dev) as conn:

            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            result = conn.run_cmd('show onu wan-cfg %s index %s' % (self.get_onu_id(sn), index))

        return extract_wan_cfg(result)

    def del_onu_wan_cfg(self, sn, index):
        """删除指定的ONU WAN配置。等同于执行命令no onu wan-cfg。

        Args:
            sn (str): 要删除的ONU SN
            index (int): 要删除的WAN index
        """
        validate_type('sn', sn, str)
        validate_type('index', index, int)

        # 检查要删除的wan配置是否存在
        wanCfgRet = self.get_onu_wan_cfg(sn, index)
        if None == wanCfgRet:
            return


        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))

            wanCfg = wanCfgRet.copy()
            if len(wanCfg['fe']) != '0':
                wanCfg['fe'] = [ ]
            
            if len(wanCfg['ssid']) != '0':
                wanCfg['ssid'] = [ ]

            self.set_onu_wan_cfg(**wanCfg)

            conn.run_cmd('no onu wan-cfg %s index %s' % (self.get_onu_id(sn), index))

    def get_onu_statistics(self, sn):
        """获取ONU统计信息。等同于执行命令show onu statistics。

        Args:
            sn (str): ONU SN

        Returns:
            dict: 包含ONU统计信息的字典。
        """
        validate_type('sn', sn, str)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            result = conn.run_cmd('show onu statistics %s' % self.get_onu_id(sn))
        
        return extract_onu_statistics(result)

    def add_bandwidth_profile(self, name, usCir, usPir, usFir, dsCir, dsPir):
        """增加Bandwidth Profile。等同于执行命令bandwidth-profile add。

        Args:
            name (str): Profile名称
            usCir (int): upstream committed information rate
            usPir (int): upstream peak information rate
            usFir (int): upstream fix information rate
            dsCir (int): downstream committed information rate
            dsPir (int): downstream peak information rate
        """
        validate_type('name', name, str)
        validate_type('usCir', usCir, int)
        validate_type('usPir', usPir, int)
        validate_type('usFir', usFir, int)
        validate_type('dsCir', dsCir, int)
        validate_type('dsPir', dsPir, int)

        # bandwidth profile name should not exist
        assert self.query_bandwidth_profile_id_by_name(name) == None

        # add bandwidth profile
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            # conn.run_cmd('bandwidth-profile add %s upstream cir %s pir %s fir %s downstream cir %s pir %s' % (name, usCir, usPir, usFir, dsCir, dsPir))
            conn.run_cmd('bandwidth-profile add %s upstream-pir %s downstream-pir %s upstream-cir %s downstream-cir %s upstream-fir %s' % (name, usPir, dsPir, usCir, dsCir, usFir))

        assert self.exist_bandwidth_profile(name, usCir, usPir, usFir, dsCir, dsPir)

    def not_exist_bandwidth_profile(self, nameOrId):
        """检查Bandwidth Profile是否不存在。

        Args:
            nameOrId (str或int): Bandwidth Profile的名称或ID

        Returns:
            bool: True，不存在；False，存在。
        """
        if type(nameOrId) != int and type(nameOrId) != str:
            raise RuntimeWarning('非法的nameOrId类型')
        
        profiles = self.get_bandwidth_profile()
        
        for profile in profiles:
            if type(nameOrId) == int and profile['Id'] == nameOrId:
                return False
            
            if type(nameOrId) == str and profile['Name'] == nameOrId:
                return False

        return True 

    def exist_bandwidth_profile(self, nameOrId, usCir, usPir, usFir, dsCir, dsPir):
        """检查Bandwidth Profile是否存在。

        Args:
            nameOrId (str或int): Bandwidth Profile的名称或ID
            usCir (int): upstream committed information rate
            usPir (int): upstream peak information rate
            usFir (int): upstream fix information rate
            dsCir (int): downstream committed information rate
            dsPir (int): downstream peak information rate

        Returns:
            bool: True，存在；False，不存在。
        """
        if type(nameOrId) != int and type(nameOrId) != str:
            raise RuntimeWarning('非法的nameOrId类型')
        
        validate_type('usCir', usCir, int)
        validate_type('usPir', usPir, int)
        validate_type('usFir', usFir, int)
        validate_type('dsCir', dsCir, int)
        validate_type('dsPir', dsPir, int)

        profiles = self.get_bandwidth_profile()

        for profile in profiles:
            if type(nameOrId) == int and profile['Id'] == nameOrId:
                if profile['upMin'] == usCir \
                and profile['upMax'] == usPir \
                and profile['upFix'] == usFir \
                and profile['downMin'] == dsCir \
                and profile['downMax'] == dsPir:
                    return True

            if type(nameOrId) == str and profile['Name'] == nameOrId:
                if profile['upMin'] == usCir \
                and profile['upMax'] == usPir \
                and profile['upFix'] == usFir \
                and profile['downMin'] == dsCir \
                and profile['downMax'] == dsPir:
                    return True
        
        return False

    def modify_bandwidth_profile(self, nameOrId, usCir, usPir, usFir, dsCir, dsPir):
        """修改Bandwidth Profile。等同于执行bandwidth-profile modify命令。

        Args:
            nameOrId (str或int): Bandwidth Profile的名称或ID
            usCir (int): upstream committed information rate
            usPir (int): upstream peak information rate
            usFir (int): upstream fix information rate
            dsCir (int): downstream committed information rate
            dsPir (int): downstream peak information rate

        """
        if type(nameOrId) != int and type(nameOrId) != str:
            raise RuntimeWarning('非法的nameOrId类型')
        
        validate_type('usCir', usCir, int)
        validate_type('usPir', usPir, int)
        validate_type('usFir', usFir, int)
        validate_type('dsCir', dsCir, int)
        validate_type('dsPir', dsPir, int)


        if type(nameOrId) == int:
            nameOrId = 'id %s' % nameOrId
        else:   # type(nameOrId) == str
            nameOrId = 'name %s' % nameOrId

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('bandwidth-profile modify %s upstream cir %s pir %s fir %s downstream cir %s pir %s' % (nameOrId, usCir, usPir, usFir, dsCir, dsPir))
        
        assert self.exist_bandwidth_profile(nameOrId, usCir, usPir, usFir, dsCir, dsPir)

    def del_bandwidth_profile(self, nameOrId):
        """删除Bandwidth Profile。等同于执行bandwidth-profile delete命令。

        Args:
            nameOrId (str或int): Bandwidth Profile的名称或ID
        """
        if type(nameOrId) != int and type(nameOrId) != str:
            raise RuntimeWarning('非法的nameOrId类型')

        prfId = None 
        if type(nameOrId) == int:
            prfId = nameOrId
            nameOrId = 'id %s' % nameOrId
        else:
            prfId = self.query_bandwidth_profile_id_by_name(nameOrId)
            nameOrId = 'name %s' % nameOrId

        for onu in self.get_authorization():
            prof = self.get_onu_bandwidth_profile(onu['Onu'])
            if prof['prfId'] == prfId:
                self.clear_onu_bandwithd_profile(onu['Onu'])

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('bandwidth-profile delete %s' % (nameOrId))
        
        assert self.not_exist_bandwidth_profile(nameOrId)

    def get_bandwidth_profile(self, id='all'):
        """获取指定ID的Bandwidth Profile。等同于show bandwidth-profile命令。

        Args:
            id (str, optional): 要获取的profile Id名称。默认为'all'，即获取全部。

        Returns:
            list: 包含Bandwidth profile信息的列表
        """
        if type(id) == str:
            assert id == 'all'
        else:
            assert type(id) == int

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show bandwidth-profile %s' % id)
        
        ret = extract_bandwidth_profile(result)

        return ret

    def query_bandwidth_profile_id_by_name(self, name):
        """根据Profile 名称查询对应的ID。

        Args:
            name (str): 要查询Bandwidth Profile的名称

        Returns:
            int: Bandwidth Profile的ID。查不到，返回None。
        """
        validate_type('name', name, str)

        allProfiles = self.get_bandwidth_profile()
        for profile in allProfiles:
            if profile['Name'] == name:
                return int(profile['Id'])
        
        return None

    def clear_bandwidth_profile(self):
        """清理所有Bandwidth Profile。
        """
        profiles = self.get_bandwidth_profile()
        
        def delFunc(profile):
            id = profile['Id']
            self.del_bandwidth_profile(id)

        run_by_thread_pool(delFunc, profiles, 5)

    def set_onu_bandwidth_profile(self, sn, profileIdOrName):
        """为ONU关联带宽模板。等同于执行onu bandwidth-profile命令。

        Args:
            sn (str): ONU SN
            profileIdOrName (int或str): 带宽模板的ID或者名称
        """
        validate_type('sn', sn, str)
        assert type(profileIdOrName) == int or type(profileIdOrName) == str

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))

            if type(profileIdOrName) == int:
                strProfile = 'profile-id %s' % profileIdOrName
            else:
                strProfile = 'profile-name %s' % profileIdOrName

            conn.run_cmd('onu bandwidth-profile %s %s' % (self.get_onu_id(sn), strProfile))


            if type(profileIdOrName) == str:
                id = self.query_bandwidth_profile_id_by_name(profileIdOrName)
            else:
                id = profileIdOrName

            ret = self.get_onu_bandwidth_profile(sn)
            try:
                assert ret['prfId'] == id
            except KeyError as ke:
                logging.getLogger().error(ret)
                raise RuntimeWarning('带宽模板关联验证失败')

    def clear_onu_bandwithd_profile(self, sn):
        """取消ONU带宽模板的关联。

        Args:
            sn (str): 要取消模板关联的ONU SN
        """
        validate_type('sn', sn, str)

        self.set_onu_bandwidth_profile(sn, 0)

        ret = self.get_onu_bandwidth_profile(sn)

        try:
            assert ret['prfId'] == 0
        except KeyError as ke:
            logging.getLogger().error(ret)
            raise RuntimeWarning('带宽模板关联取消失败')

    def get_onu_bandwidth_profile(self, sn):
        """查询ONU关联的带宽模板信息。等同于执行命令。

        Args:
            sn (str): 要查询的ONU SN

        Returns:
            dict: 包含ONU所关联带宽模板的信息。
        """
        validate_type('sn', sn, str)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            result = conn.run_cmd('show onu bandwidth %s' % self.get_onu_id(sn))
        
        ret = extract_onu_bandwidth(result)
        ret['prfId'] = ret['prfId'] + 1

        return ret

    def set_onu_bandwidth(self, sn, usCir, usPir, usFir, dsPir):
        """设置ONU带宽。等同于执行onu bandwidth命令。

        Args:
            sn (str): ONU SN
            usCir (int): upstream committed information rate
            usPir (int): upstream peak information rate
            usFir (int): upstream fix information rate
            dsPir (int): downstream peak information rate
        """
        validate_type('sn', sn, str)
        validate_type('usCir', usCir, int)
        validate_type('usPir', usPir, int)
        validate_type('usFir', usFir, int)
        validate_type('dsPir', dsPir, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            conn.run_cmd('onu bandwidth %s upstream-pir %s downstream-pir %s upstream-cir %s upstream-fir %s' % (self.get_onu_id(sn), usPir, dsPir, usCir, usFir))
        

        ret = self.get_onu_bandwidth_profile(sn)

        actualUsCir = ret['upAssureBand']
        actualUsPir = ret['upMaxband']
        actualUsFir = ret['upFixband']
        actualDsPir = ret['downMaxband']

        assert actualUsCir == usCir \
            and actualUsPir == usPir \
                and actualUsFir == usFir \
                        and actualDsPir == dsPir

    def set_pon_bandwidth(self, slot, port,  usPir, dsPir):
        """设置PON口带宽。等同于执行bandwidth命令。

        Args:
            slot (int): 槽位号
            port (int): 端口号
            usPir (int): 上行Pir
            dsPir (int): 下行Pir
        """
        validate_type('slot', slot, int)
        validate_type('port', port, int)
        validate_type('usPir', usPir, int)
        validate_type('dsPir', dsPir, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % (slot, port))
            if usPir != dsPir:
                conn.run_cmd('bandwidth %s %s' % ('upstream', usPir))
                conn.run_cmd('bandwidth %s %s' % ('downstream', dsPir))
            else:
                conn.run_cmd('bandwidth %s %s' % ('all', dsPir))

        ret = self.get_pon_bandwidth(slot, port)
        assert ret['UP'] == usPir and ret['DOWN'] == dsPir

    def get_pon_bandwidth(self, slot, port):
        """查询PON口带宽。等同于执行show bandwidth命令。

        Args:
            slot (int): 槽位号
            port (int): 端口号

        Returns:
            dict: 含带宽信息的字典。
        """
        validate_type('slot', slot, int)
        validate_type('port', port, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % (slot, port))
            result =  conn.run_cmd('show bandwidth')
        
        ret = extract_bandwidth(result)

        return ret

    def set_onu_port_service_bandwidth(self, sn, eth, serviceIndex, usProfileId, dsProfileId):
        """设置端口业务带宽模板。等同于执行onu port service-bandwidth命令。

        Args:
            sn (str): ONU SN
            eth (int): 端口号
            serviceIndex (int): 业务Index
            usProfileId (int): 上行带宽模板
            dsProfileId (int): 下行带宽模板
        """
        validate_type('sn', sn, str)
        validate_type('eth', eth, int)
        validate_type('serviceIndex', serviceIndex, int)
        validate_type('usProfileId', usProfileId, int)
        validate_type('dsProfileId', dsProfileId, int)


        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            conn.run_cmd('onu port service-bandwith %s eth %s service %s upstream-profile %s downstream-profile %s' % (self.get_onu_id(sn), eth, serviceIndex, usProfileId, dsProfileId))

    def set_onu_port_policy(self, sn, eth, usEnable, usCir, usCbs, usEbs, dsEnable, dsCir, dsPir):
        """设置ONU端口策略。等同于执行onu port policing命令。

        Args:
            sn (str): ONU SN
            eth (int): 网口号
            usEnable (str): enable，使能上行策略；disable，去使能上行策略。
            usCir (int): 上行CIR
            usCbs (int): 上行CBS
            usEbs (int): 上行EBS
            dsEnable (str): enable，使能下行策略；disable，去使能下行策略。
            dsCir (int): 下行CIR
            dsPir (int): 下行PIR
        """
        validate_type('sn', sn, str)
        validate_type('eth', eth, int)
        validate_type('usEnable', usEnable, str)
        validate_type('usCir', usCir, int)
        validate_type('usCbs', usCbs, int)
        validate_type('usEbs', usEbs, int)
        validate_type('dsEnable', dsEnable, str)
        validate_type('dsCir', dsCir, int)
        validate_type('dsPir', dsPir, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            conn.run_cmd('onu port policing %s eth %s upstream %s cir %s cbs %s ebs %s downstream %s cir %s pir %s' % (self.get_onu_id(sn), eth, usEnable, usCir, usCbs, usEbs, dsEnable, dsCir, dsPir))

    def set_onu_layer3_rate_limit(self, sn, wanIndex, usProfileId, dsProfileId):
        """设置ONU三层限速。等同于执行onu layer3-ratelimit-profile命令。

        Args:
            sn (str): ONU SN
            wanIndex (int): WAN Index
            usProfileId (int): 上行限速模板ProfileId
            dsProfileId (int): 下行限速模板ProfileId
        """
        validate_type('sn', sn, str)
        validate_type('wanIndex', wanIndex, int)
        validate_type('usProfileId', usProfileId, int)
        validate_type('dsProfileId', dsProfileId, int)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))
            conn.run_cmd('onu layer3-ratelimit-profile %s %s upstream-profile-id %s downstream-profile-id %s' % (self.get_onu_id(sn), wanIndex, usProfileId, dsProfileId))

        found = False
        profiles = self.get_onu_layer3_rate_limit(sn)
        for profile in profiles:
            if profile['Wan index'] == wanIndex:
                assert profile['Up bandwidth profile id'] == usProfileId if usProfileId != -1 else 65535
                assert profile['Down bandwidth profile id'] == dsProfileId if dsProfileId != -1 else 65535
                found = True
                break
        
        assert found, '三层限速设置失败: %s' % profiles

    def get_onu_layer3_rate_limit(self, sn, state=None):
        """获取ONU 3层限速配置信息。等同于执行show onu layer3-ratelimit-profile命令。

        Args:
            sn (str): ONU sn
            state (str, optional): 查询哪种状态的限速. 默认为None，查询offline和online两种状态的限速信息。

        Returns:
            list: 包含限速信息的列表
        """
        validate_type('sn', sn, str)
        if state != None:
            validate_type('state', state, str)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % self.get_onu_position(sn))

            onuId = self.get_onu_id(sn)
            if state == None:
                

                result1 = conn.run_cmd('show onu layer3-ratelimit-profile %s %s' % (onuId, 'offline'))
                ret1 = extract_onu_layer3_rate_limit_profile(result1)

                result2 = conn.run_cmd('show onu layer3-ratelimit-profile %s %s' % (onuId, 'online'))
                ret2 = extract_onu_layer3_rate_limit_profile(result2)

                ret = ret1 + ret2
            else:
                result = conn.run_cmd('show onu layer3-ratelimit-profile %s %s' % (onuId, state))
                ret = extract_onu_layer3_rate_limit_profile(result)
        
        return ret

    def del_onu_layer3_rate_limit(self, sn, wanIndex):
        """删除指定ONU的三层限速。等同于执行onu layer3-ratelimit-profile命令。

        Args:
            sn (str): ONU SN
            wanIndex (int): WAN Index
        """
        validate_type('sn', sn, str)
        validate_type('wanIndex', wanIndex, int)
        self.set_onu_layer3_rate_limit(sn, wanIndex, -1, -1)
    
    def set_service_vlan(self, name, vlan, vlan_type):
        """设置业务VLAN

        Args:
            name (str): 业务VLAN名称
            vlan (str): 业务VLAN范围。如 1000 - 2000， 或 1000。
            vlan_type (str): 业务VLAN类型。仅限'cnc', 'data', 'iptv', 'ngn', 'system', 'uplinksub', 'vod', 'voip'类型。
        """
        validate_type('name', name, str)
        validate_type('vlan', vlan, str)
        validate_type('type', vlan_type, str)

        ValidTypesList = [ 'cnc', 'data', 'iptv', 'ngn', 'system', 'uplinksub', 'vod', 'voip']
        assert vlan_type in ValidTypesList, '无效的业务VLAN类型'

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('service-vlan %s %s type %s' % (name, vlan.replace('-', ' to '), vlan_type))

        assert self.exist_service_vlan(name, vlan, vlan_type)

    def get_service_vlan(self):
        """获取业务VLAN信息。等同于执行show service-vlan命令。

        Returns:
            list: 包含业务VLAN信息字典的列表。
        """

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show service-vlan')

        return extract_service_vlan(result)

    def del_service_vlan(self, name):
        """删除业务VLAN信息。等同于执行no service-vlan命令。

        Args:
            name (str): 业务VLAN的名称。
        """
        validate_type('name', name, str)

        if not self.exist_service_vlan(name):
            return

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('no service-vlan %s' % name)
        
        assert not self.exist_service_vlan(name)

    def clear_service_vlan(self):
        """清空所有Service Vlan
        """
        def delFunc(info):
            self.del_service_vlan(info['name'])

        run_by_thread_pool(delFunc, self.get_service_vlan())

    def exist_service_vlan(self, name, vlan_range=None, service_type=None):
        """检查指定的业务VLAN是否存在。

        Args:
            name (str): 业务VLAN名称
            vlan_range (str, optional): 业务VLAN的范围. 默认为None，不指定要检查的范围。
            service_type (str, optional): 业务VLAN的类型. 默认为None，不指定要检查的业务类型。

        Returns:
            bool: True，所指定的业务VLAN，VLAN范围和类型存在; False，不存在。
        """
        validate_type('name', name, str)
        if vlan_range != None:
            validate_type('vlan', vlan_range, str)
        if service_type != None:
            validate_type('type', service_type, str)

        svlanList = self.get_service_vlan()
        for svlanDict in svlanList:
            if svlanDict['name'] == name:
                if vlan_range != None:
                    expectedVlanList = re.split('\s*[~-]\s*', vlan_range)
                    actualVlanList = re.split('\s*[~-]\s*', str(svlanDict['vlan range']))
                    if expectedVlanList != actualVlanList:
                        return False
                    else:
                        if service_type == None:
                            return True
                        else:
                            if service_type == svlanDict['type']:
                                return True
                            else:
                                return False
                else:
                    return True

        return False

    def add_onu_qinq_classification_profile(self, name, fieldValueOpList):
        """新增onuqinq-classfication-profile。

        Args:
            name (str): Profile名称
            fieldValueOpList (list): (field, value, op)元组列表。如，[(0, '000000000000', 4)]。
        """
        validate_type('name', name, str)
        validate_type('fieldValueOpList', fieldValueOpList, list)

        if self.exist_onu_qinq_classification_profile(name):
            logging.getLogger().warning('名为%s的onuqinq-classification-profile已经存在，将会覆盖它' % name)

        self._add_or_modify_onu_qinq_classification_profile(name, fieldValueOpList, op='add')

    def modify_onu_qinq_classification_profile(self, name, fieldValueOpList):
        """修改onuqinq-classfication-profile。

        Args:
            name (str): Profile名称
            fieldValueOpList (list): (field, value, op)元组列表。如，[(0, '000000000000', 4)]。
        """
        validate_type('name', name, str)
        validate_type('fieldValueOpList', fieldValueOpList, list)
        
        assert self.exist_onu_qinq_classification_profile(name)

        self._add_or_modify_onu_qinq_classification_profile(name, fieldValueOpList, op='modify')

    def _add_or_modify_onu_qinq_classification_profile(self, name, fieldValueOpList, op='add'):
        """增加或修改onuqinq-classfication-profile。

        Args:
            name (str): Profile名称
            fieldValueOpList (list): (field, value, op)元组列表。如，[(0, '000000000000', 4)]。
            op (str, optional): 默认为'add'，增加。还可以为'modify'。
        """
        validate_type('name', name, str)
        validate_type('fieldValueOpList', fieldValueOpList, list)
        validate_type('op', op, str)
        
        fieldValueOpStr = ''
        for param in fieldValueOpList:
            fieldValueOpStr = fieldValueOpStr + ' %s %s %s' % param
        fieldValueOpStr = fieldValueOpStr.strip()

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('onuqinq-classification-profile %s %s %s' % (op, name, fieldValueOpStr))
        
        assert self.exist_onu_qinq_classification_profile(name)        

    def get_onu_qinq_classification_profile(self, name=None):
        """查询onuqinq-classfication-profile。等同于执行show onuqinq-classification-profile命令。

        Args:
            name (str): 要查询Profile的名称
        
        Returns:
            list: 包含Profile信息字典的列表
        """
        if name != None:
            validate_type('name', name, str)

        if name:
            cmdStr = 'name %s' % name
        else:
            cmdStr = 'all'

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show onuqinq-classification-profile %s' % cmdStr)
        
        ret = extract_onu_qinq_classification_profile(result)

        return ret

    def del_onu_qinq_classification_profile(self, name):
        """删除onuqinq-classfication-profile。等同于执行命令。

        Args:
            name (str): 要删除的Profile的名称
        """
        validate_type('name', name, str)

        if not self.exist_onu_qinq_classification_profile(name):
            return

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('onuqinq-classification-profile delete %s' % name)

        assert not self.exist_onu_qinq_classification_profile(name)

    def exist_onu_qinq_classification_profile(self, name):
        """检查onuqinq-classfication-profile的是否存在。

        Args:
            name (str): Profile名称。

        Returns:
            bool: True，存在；False，不存在。
        """
        validate_type('name', name, str)
        
        profiles = self.get_onu_qinq_classification_profile()

        for profile in profiles:
            if profile['name'] == name:
                return True
        
        return False

    def add_olt_qinq_domain(self, name):
        """新增oltqinq-domain。等同于执行oltqinq-domain add命令。

        Args:
            name (str): oltqinq-domain的名称。
        """
        validate_type('name', name, str)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('oltqinq-domain add %s' % name)
        
        # verify set successfully
        assert self.exist_olt_qinq_domain(name)

    def get_olt_qinq_domain(self, nameOrIndex):
        """获取oltqinq-domain。等同于执行命令。

        Args:
            nameOrIndex (str或int): 要获取oltqinq-domain的名称。

        Returns:
            dict: 包含oltqinq-domain信息的字典。
        """
        assert type(nameOrIndex) == str or type(nameOrIndex) == int, "nameOrIndex只接受str或int类型"

        if type(nameOrIndex) == str and not nameOrIndex.isdigit():
            strCmdArgs = nameOrIndex
        else:
            strCmdArgs = "index %s" % nameOrIndex

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show oltqinq-domain %s' % strCmdArgs)

        return extract_olt_qinq_domain(result)

    def exist_olt_qinq_domain(self, name):
        """检查指定的oltqinq-domain是否存在。

        Args:
            name (str): 要检查的oltqinq-domain域的名称。
        
        Return:
            bool: True，存在；False，不存在。
        """
        validate_type('name', name, str)

        profile = self.get_olt_qinq_domain(name)
        if profile == None:
            return False
        
        return True

    def set_olt_qinq_domain_service_count(self, name, count):
        """设置oltqinq-domain服务数量。等同于执行oltqinq-domain modify命令。

        Args:
            name (str): 要设置的oltqinq-domain。
            count (int): 服务的数量。
        """
        validate_type('name', name, str)
        validate_type('count', count, int)
        
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('oltqinq-domain modify %s service-count %s' % (name, count))
        
        # verify
        profile = self.get_olt_qinq_domain(name)
        assert len(profile['services']) == count

    def set_olt_qinq_domain_service_type(self, name, serviceIndex, type):
        """设置oltqinq-domian业务类型。等同执行oltqinq-domain modify命令。
        
        Args:
            name (str): oltqinq-domain域名称
            serviceIndex (int): 业务的索引号
            type (str): 业务的类型。
        """
        validate_type('name', name, str)
        validate_type('serviceIndex', serviceIndex, int)
        validate_type('type', type, str)


        profile = self.get_olt_qinq_domain(name)
        assert profile != None, "oltqinq-domain不存在"
        assert serviceIndex <= profile['count'], "业务索引号(%s)超出范围, 仅有%s条业务。" % (serviceIndex, profile['count'])

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('oltqinq-domain modify %s service %s type %s' % (name, serviceIndex, type))
        
        # NEED VERIFY
        profile = self.get_olt_qinq_domain(name)
        for service in profile['services']:
            if service['no'] == serviceIndex and service['type'] == type:
                return

        raise RuntimeWarning('设置oltqinq-domian业务类型失败')

    def del_olt_qinq_domain(self, name):
        """删除oltqinq-domian域。

        Args:
            name (str): oltqinq-domain域名称。
        """
        validate_type('name', name, str)

        if not self.exist_olt_qinq_domain(name):
            return
        
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('oltqinq-domain delete %s' % name)

        # verify
        assert not self.exist_olt_qinq_domain(name)

    def set_olt_qinq_domain_stream_rules(self, name, serviceIndex, stream, ruleList):
        """设置oltqinq-domian上下行流识别规则。等同于执行oltqinq-domain命令。

        Args:
            name (str): oltqinq-domian域名称
            serviceIndex (int): 业务索引号
            stream (str): 上行流还是下行流。上行，upstream；下行，downstream
            ruleList (list): (field-id, value, condition)形式的元组列表
        """
        validate_type('name', name, str)
        validate_type('serviceIndex', serviceIndex, int)
        validate_type('stream', stream, str)
        validate_type('ruleList', ruleList, list)

        # 将元组列表转换为字符串        
        strRule = list_to_str(ruleList, 'field-id %s value %s condition %s')

        # 执行命令
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('oltqinq-domain %s service %s classification %s %s' % (name, serviceIndex, stream, strRule))

        # 验证
        profile = self.get_olt_qinq_domain(name)
        serviceEntry = None
        for service in profile['services']:
            if service['no'] == serviceIndex:
                serviceEntry = service
                break
        assert serviceEntry != None

        streamRules = serviceEntry['rule'][stream]

        for fvo, rule in zip(ruleList, streamRules):
            assert fvo == rule, '%s != %s' % (fvo, rule)

    def set_olt_qinq_domain_stream_vlan(self, name, serviceIndex, vlanRuleList):
        """设置oltqinq-domian VLAN规则。等同于执行oltqinq-domain命令。
        
        Args:
            name (str): oltqinq-domain域名称
            serviceIndex (int): 业务类型
            vlanRuleList (list): vlan规则的元组列表。如，[(1, 'null', 'null', 'transparent', '33024', 'null', 'null')]。几个参数分别对应vlan层数，用户vid，用户cos，动作，目标tpid，目标cos和目标vid。            
        """
        validate_type('name', name, str)
        validate_type('serviceIndex', serviceIndex, int)
        validate_type('vlanRuleList', vlanRuleList, list)

        # 将规则列表转换为字符串
        strVlanRule = list_to_str(vlanRuleList, 'vlan %s user-vlanid %s user-cos %s %s tpid %s cos %s vlanid %s')

        # run command
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('oltqinq-domain %s service %s %s' % (name, serviceIndex, strVlanRule))

        # verify
        profile = self.get_olt_qinq_domain(name)
        serviceEntry = None
        for service in profile['services']:
            if service['no'] == serviceIndex:
                serviceEntry = service
                break
        assert serviceEntry != None

        vlanRules = serviceEntry['vlan']

        for rule, vlanRule in zip(vlanRuleList, vlanRules):
            assert rule == vlanRule, '%s != %s' % (rule, vlanRule)

    def bound_olt_qinq_domain(self, slot, port, name):
        """绑定oltqinq-domain域。等同于执行oltqinq-domain命令。

        Args:
            slot (int): 要绑定的槽位号
            port (int): 要绑定的端口号
            name (str): 要绑定的QinQ域的名称
        """
        validate_type('slot', slot, int)
        validate_type('port', port, int)
        validate_type('name', name, str)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % (slot, port))
            conn.run_cmd('oltqinq-domain %s' % name)

    def unbound_olt_qinq_domain(self, slot, port, name):
        """取消绑定oltqinq-domain。等同于执行no oltqinq-domain命令。

        Args:
            slot (int): 要取消绑定的槽位号
            port (int): 要取消绑定的端口号
            name (str): 要取消绑定的QinQ域的名称
        """
        validate_type('slot', slot, int)
        validate_type('port', port, int)
        validate_type('name', name, str)

        if not self.is_olt_qinq_domain_bound(slot, port, name):
            return

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % (slot, port))
            conn.run_cmd('no oltqinq-domain %s' % name)

    def is_olt_qinq_domain_bound(self, slot, port, name):
        """检查指定oltqinq-domain是否绑定。等同于执行show oltqinq-domain bound-info命令。

        Args:
            slot (int): 槽位号
            port (int): 端口号
            name (str): QinQ域名称
        Returns:
            bool: True, 绑定；Flase，未绑定。
        """
        validate_type('slot', slot, int)
        validate_type('port', port, int)
        validate_type('name', name, str)

        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            conn.run_cmd('interface pon 1/%s/%s' % (slot, port))
            try:
                result = conn.run_cmd('show oltqinq-domain bound-info %s' % name)
                ret = extract_olt_qinq_domain_bound_info(result)
                return ret == (value(slot), value(port))
            except AssertionError as ae:
                return False

    def clear_olt_qinq_domain(self):
        """清空所有OLTQinQDomain
        """
        def delFunc(id):
            try:
                self.del_olt_qinq_domain(self.get_olt_qinq_domain(id)['name'])
            except RuntimeWarning:
                logging.getLogger().debug('要删除的OLTQinQDomain(%s)不存在' % id)
                return
            
            logging.getLogger().debug('删除OLTQinQDomain(%s)成功' % id)
        
        run_by_thread_pool(delFunc, range(1,20001))

    def get_current_alarm(self):
        """获取OLT上面当前产生的告警
        """
        with Connection.get(self.olt_dev) as conn:
            conn.run_cmd('config')
            result = conn.run_cmd('show alarm current')
        
        ret = extract_current_alarm(result)

        return ret


__all__ = [

    'OLTCLI_AN6K_17'
]