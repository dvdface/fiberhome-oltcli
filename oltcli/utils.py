import random
import re
import os
import sys
from ping_cmd import host
from types import FunctionType, MethodType
import time
import logging
import pyshark
import inspect
import shutil
from dateutil.parser import parse
from hashlib import md5
import threadpool
import tempfile
import csv
import pathlib

def value(strValue, maxValue=None):
    """将字符串类型表示的值尽可能的转换成对应格式的类型。如，'1.0'转换成浮点型，'1'或'0xFF'转换成整型。

    Args:
        strValue (str or None): 要转换的字符串格式的值，为None时不转换，直接返回。
        maxValue (int, optional): 当指定该参数时，如果转换的int类型的值为maxValue将会返回'null'。如，指定65535，当值strValue为'65535'时，自动转换为'null'，而非整数。 默认为None，不进行判定和转换。

    Returns:
        any: 转换后的值，'1'将为int类型的1， '1.0'将为float类型的1.0， '1920-10-1 10:11:11'转换为datetime格式，'hello'仍然为'hello'
    """
    # 如果为None不做转换
    if strValue == None:
        return strValue
    else:
        validate_type('strValue', strValue, str)

    # 去掉首尾空格
    strValue = strValue.strip()
    
    intExp = re.compile('^-?(0x|0X)?\d+$') # 匹配 10和16进制的±整数
    floatExp = re.compile('^-?\d+.\d+$') # 匹配 10进制的±浮点数
    datetimeExp = re.compile("\d{4,4}-\d{1,2}-\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}")

    if intExp.match(strValue):
        # 如果是整数类型
        intValue = int(strValue, 10 if strValue.find('0x') == -1 and  strValue.find('0x') == -1 else 16)
        if maxValue != None and intValue == maxValue:
            # 当设置了达到最大值的选项，且满足时，返回'null'
            return 'null'
        else:
            return intValue
    elif floatExp.match(strValue):
        # 如果是浮点类型
        return float(strValue)
    elif datetimeExp.match(strValue):
        # 如果是日期类型
        if strValue != '0000-00-00 00:00:00':
            return parse(strValue)
        else:
            return None
    else:
        # 不识别字符串的不处理
        return strValue

def validate_type(varName, varValue, expectedType):
    """验证变量的类型是否满足要求。

    Args:
        varName (str): 变量名称
        varValue (any): 变量的值
        expectedType (any或list): 希望的类型
    """
    if type(expectedType) == list:
        assert type(varValue) in expectedType, "%s应当为%s类型, 但为%s类型" % (varName, expectedType, type(varValue))
    else:
        assert type(varValue) == expectedType, "%s应当为%s类型, 但为%s类型" % (varName, expectedType, type(varValue))

def validate_ip_addr(ip):
    """验证IP地址是否可达。

    Args:
        ip (str): a.b.c.d格式的IP地址
    """

    assert type(ip) == str, "IP地址应当为str类型，但为%s类型" % type(ip)

    assert is_valid_ipv4_addr(ip), "IP地址格式无效: %s" % ip

    assert is_ip_connectable(ip), "IP地址不可达: %s" % ip

def validate_int_range(intValue, min, max):
    """验证int值是否落在[min, max]区间中。

    Args:
        intValue (int): 要验证范围的值
        min (int): 最小值
        max (int): 最大值
    """
    assert min <= intValue and intValue <= max, "%s超出范围[%s, %s]" % (intValue, min, max)

def validate_key(name, expectedKey, expectedType):
    """验证字典是否包含指定类型的key

    Args:
        name (dict): 要进行检查的字典
        expectedKey (Any): 要进行检查的键名
        expectedType (Any或list): 要确认键值的类型
    """
    
    assert expectedKey in name.keys(), "字典中不包含该键：%s" % expectedKey
    if type(expectedType) != list:
        assert type(name[expectedKey]) == expectedType, "字典中该键值的类型不符合预期，预期%s，实际%s" % (expectedType, type(name[expectedKey]))
    else:
        assert type(name[expectedKey]) in expectedType, "字典中该键值的类型不符合预期，预期%s，实际%s" % (expectedType, type(name[expectedKey]))

def move(file, dstDir):
    """将文件移动到目标目录中。如果目录不存在则创建。

    Args:
        file (str): 文件路径
        dstDir (str): 目标目录路径
    
    Returns:
        str: 文件新的路径
    """
    file = os.path.abspath(file)
    if not os.path.exists(file):
        return

    absDstDir = os.path.abspath(dstDir)

    if not os.path.exists(os.path.dirname(absDstDir)):
        os.mkdir(os.path.dirname(absDstDir))
    
    if not os.path.exists(absDstDir):
        os.mkdir(absDstDir)
    shutil.move(file, absDstDir)

    return os.path.join(os.path.abspath(absDstDir), os.path.basename(file))

def merge(base, more):
    """将more字典合并入base字典中，同名的key值将使用more覆盖base中的值。
    Args:
        base (dict): 基准字典
        more (dict): 更新字典

    Returns:
        dict: 合并过后的字典
    """
    assert type(base) == dict and type(more) == dict

    b = dict(base)
    u = dict(more)

    b.update(u)

    return b

def expand_list(tupleList):
    """将[(x, [y1, y2, y3]), ...]形态的列表展开为[(x, y1), (x, y2), (x, y3), ...]形态

    Args:
        tupleList (list): [(x, [y1, y2, y3]), ...]形态的列表

    Returns:
        list: [(x, y1), (x, y2), (x, y3), ...]形态的列表
    """
    ret = [ ]
    for t in tupleList:
        x, yList = t
        for y in yList:
            ret.append((x, y))
    
    return ret

def break_frame_slot_port(port):
    """提取frame/slot/port字串中的slot和port信息。如，'1/9/2'提取为(1, 9 , 2)
    Args:
        strPort (str): frame/slot/port字串

    Returns:
        tuple: (frame, slot, port)元组
    """
    portExpr = re.compile('(\d+)/(\d+)/(\d+)')
    match = portExpr.match(port)
    assert None != match
    f, s, p = match.groups()
    
    return value(f), value(s), value(p)

def count_packets(pcapFile, filter):
    """统计给定的Pcap文件中满足过滤器条件的个数

    Args:
        pcapFile (str): pcap/pcapng文件路径
        filter (str): Wireshark过滤表达式
    
    Returns:
        满足条件的包的个数
    """
    validate_type('pcapFile', pcapFile, str)
    validate_type('filter', filter, str)

    assert os.path.exists(pcapFile), "指定的文件不存在: %s" % pcapFile

    pkts = pyshark.FileCapture(pcapFile, display_filter=filter)
    count = 0
    for pkt in pkts:
        count = count + 1
    
    pkts.close()
    
    return count

def get_packets_info(pcapFile, attribute, filter = None, disableProtocol = 'rtcp'):
    """从给定的Pcap文件中提取所需的信息

    Args:
        pcapFile (str): Pcap文件 
        attributes (str或list): 要获取的属性值
        filter (str, optional): 过滤Pcap文件的过滤器
        disableProtocol (str): 要禁用解析的协议。有时候pyshark调用tshark对某些协议的内容强行进一步解析时，会出现Malformed Packet的错误，这个时候把这个出现错误的解析协议屏蔽掉，避免出现异常。
    
    示例:
        获取PPPoED中PADS消息携带的Session ID，同时，还会返回eth层的源MAC和目的MAC
        getPacketsInfo(file, ['eth.src', 'eth.dst', 'pppoed.pppoe_session_id'], 'pppoe.code == 0x65')

        获取IPCP Configuration Ack消息中的IP Address，同时，还会返回eth层的源MAC和目的MAC
        getPacketsInfo(file, ['eth.src', 'eth.dst', 'ipcp.opt_ip_address'], '(ppp.code == 2) && (ppp.protocol == 0x8021) && (ipcp.opt.type == 3)')
    
    Returns:
        list: 返回包含提取字段信息(字典)的列表
    """
    validate_type('pcapFile', pcapFile, str)
    assert os.path.exists(pcapFile), "指定的文件不存在: %s" % pcapFile

    logging.getLogger().debug('文件%s的md5sum为: %s' % (pcapFile, md5sum(pcapFile)))

    pkts = pyshark.FileCapture(pcapFile, display_filter=filter, disable_protocol=disableProtocol)
    
    ret = [ ]

    try:
        for pkt in pkts:
            if type(attribute) == list:
                ret.append({})
                for attr in attribute:
                    ret[-1][attr] = value(str(eval('pkt.%s' % attr)))
                continue

            if type(attribute) == str:
                ret.append(value(str(eval('pkt.%s' % attribute))))
    finally:
        pkts.close()

    
    return ret

def wait_until_no_change(func, interval=5, overtime=600):
    """等待函数返回值不再变化

    Args:
        func (functionType): 反复调用该函数获取返回值
        interval (int, optional): 调用间隔。默认5秒。
        overtime (int, optional): 超时时长.默认600秒。
    """
    # only function can be called
    assert type(func) == FunctionType or type(func) == MethodType
    s_time = time.time()
    last_result = func()
    while True:
        logging.getLogger().info("等待%s秒后重试" % interval)
        time.sleep(interval)
        result = func()
        waittime = time.time() - s_time
        if result == last_result:
            logging.getLogger().warning("总共等待%.1f秒" % waittime)
            break
        else:
            last_result = result
            if waittime > overtime:
                raise RuntimeWarning("%s秒等待超时" % overtime)
    
    return result

def wait_for_true(condFunc, interval=1, overtime=30):
    """等待条件函数返回值为True

    Args:
        condFunc (FunctionType): 条件函数，期间反复调用，直至返回为True或者超时
        interval (int, optional): 调用间隔，单位秒。默认1秒。
        overtime (int, optional): 超时时间。默认30秒。
    """
    assert type(condFunc) == FunctionType or type(condFunc) == MethodType
    s_time = time.time()
    while overtime > (time.time() - s_time):

        if condFunc():
            logging.getLogger().warning("总共等待%.1f秒" % (time.time() - s_time))
            return
        else:
            logging.getLogger().info("已经等待%.1f秒, 等待%s秒后重试" % (time.time() - s_time, interval))
            time.sleep(interval)
    
    raise RuntimeWarning('%s秒等待超时' % overtime)

def is_ip_connectable(ipAddr):
    """检查IP地址是否可达

    Args:
        ipaddr (str): IP地址字符串

    Returns:
        bool: True，可达;  False不可达
    """
    assert is_valid_ipv4_addr(ipAddr), "IP地址非法: %s" % ipAddr
    return  0 == host.ping(ipAddr)

def is_valid_ipv4_addr(ipaddr):
    """检查IP地址格式的是否为x.x.x.x格式。

    Args:
        ipaddr (str): IP地址字符串

    Returns:
        bool: True合法，False非法
    """
    if(None == re.match("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$", ipaddr)):
        return False
    
    for n in ipaddr.split("."):
        num = int(n)
        if(num < 0 and num > 255):
            return False

    return True

def dict_to_opt(dict, prefix='', optBlackList = []):
    """将字典中的key/value转换成'key1=value1 key2=value2'这样的字符串。

    Args:
        dict (dict): 包含选项和选项值的字典。
        prefix (str): 在选项前增加的符号。指定则会增加，如，'-'，格式化为'-key1=value1 -key2=value2'
        optBlackList (list, optional): 黑名单。如果选项的key值在黑名单中，将不会格式化输出到字符串中。默认为空。
    Returns:
        str: 格式化完成后的字符串。
    """
    strCmd = ''
    for key in dict.keys():
        # key是否在黑名单中
        if key in optBlackList:
            continue
        
        # 如果选项的值为字符类型，且其中带有空格，将用引号括起来
        if type(dict[key]) == str and ' ' in dict[key]:
            strOpt = '%s%s "%s"' % (prefix, key, dict[key])
        else:
            strOpt = '%s%s %s' % (prefix, key, dict[key])
    
        # append to strCmd
        strCmd = strCmd + ' ' + strOpt
    
    return strCmd.strip() # strip space in the head and tail

def add_dollar_sign(value):
    """为给定的值加上$符号。

    Args:
        value (str or list): 可以是单串，空格分隔的长串，或者列表。

    Returns:
        str: 给定'port'，返回'$port'。给定'port1 port2'， 返回'$port1 $port2'。给定['port1', 'port2']， 返回'$port1 $port2'。
    """
    ret = ''
    for var in re.split('\s+', value.strip()) if type(value) == str else value:
        ret = ret + ' $%s' % var
    
    return ret.strip()

def list_to_str(listArg, template='%s', sep=' '):
    """将给定的列表中元素，依次使用模板格式化后，使用指定的分隔符连接为一个长串后返回。如，list2Str([1,2,3], '$%s')返回'$1 $2 $3'

    Args:
        listArg (list): 要处理的列表
        template (str): 用于格式化的模板。默认值'%s'。
    Returns:
        str: 返回的字符长串
    """
    ret = ''
    for i in listArg:
        ret = ret + sep + template % i
    return  ret.strip()

class MAC:
    """MAC类用于生成MAC地址。如，mac = MAC('00:10:94:00:00:00')， mac.next()将生成00:10:94:00:00:01的IP地址。
    """
    def __init__(self, addr='00:10:94:00:00:00'):
        """初始化MAC类

        Args:
            addr (str, optional): 指定MAC地址，生成MAC地址将从它的基础上增加而来。默认'00:10:94:00:00:00'。
        """
        self.macExp = re.compile('([A-Fa-f0-9]{2,2}):([A-Fa-f0-9]{2,2}):([A-Fa-f0-9]{2,2}):([A-Fa-f0-9]{2,2}):([A-Fa-f0-9]{2,2}):([A-Fa-f0-9]{2,2})')
        assert self.macExp.match(addr) != None, 'invalid mac addr: %s' % addr
        self.addr = addr

    def _incrHex(self, hex):
        """对给定的hex值加1，并且判断是否大于0xFF需要进位。

        Args:
            hex (str or int): 被加1的值
        
        Returns:
            tuple: 返回(是否进位， 累加后的HEX值)元组， 如，0xFF增加1后，返回(1, '0x00'), 0xFE增加1后，返回(0, '0xFF')
        """
        if type(hex) == str:
            hex = int(hex, 16)
            
        hex = hex + 1

        if hex > 255:
            return 1, '00'
        else:
            return 0, '%02x' % hex
       
    def next(self):
        """返回下个生成的MAC地址。

        Returns:
            str: 生成的MAC地址字符串。
        """
        m1, m2, m3, m4, m5, m6 = self.macExp.match(self.addr).groups()

        incr, m6 = self._incrHex(m6)
        if incr == 1:
            incr, m5 =self._incrHex(m5)
            if incr == 1:
                incr, m4 = self._incrHex(m4)
                assert incr == 0
        
        self.addr = '%s:%s:%s:%s:%s:%s' % (m1, m2, m3, m4, m5, m6)
        return self.addr

class IP:
    """IP类用于生成IP地址。如，ip = IP('192.168.0.0')， ip.next()将会生成192.168.0.1的IP地址。
    """

    def __init__(self, addr='192.168.0.0'):
        """初始化IP类

        Args:
            addr (str, optional): 指定IP网段，生成的IP地址将从该地址的基础上增加而来. 默认为'192.168.0.0'.
        """

        self.ipExp = re.compile('(\d{1,3}).(\d{1,3}).(\d{1,3}).(\d{1,3})')

        match = self.ipExp.match(addr)
        assert match != None, 'invalid ip address: %s' % addr
        a, b, c, d = match.groups()
        intA, intB, intC, intD = int(a), int(b), int(c), int(d)

        assert intD == 0, 'invalid ip address: %s, expected %s.%s.%s.0' % (addr, intA, intB, intC)

        self.addr = addr
        self.gateway = '%s.%s.%s.254' % (intA, intB, intC)

    def next(self):
        """返回下个生成的IP地址。

        Returns:
            str: 生成的IP地址字符串。
        """
                
        a, b, c, d = self.ipExp.match(self.addr).groups()
        intA, intB, intC, intD = int(a), int(b), int(c), int(d)
        intD = intD + 1
        assert intD < 254, 'out of range: %d.%d.%d.%d' % (intA, intB, intC, intD)

        self.addr = '%d.%d.%d.%d' % (intA, intB, intC, intD)

        return self.addr

class Port:
    """用于创建唯一的端口号
    """

    def __init__(self, base=1024):
        """初始化Port类。

        Args:
            base (int, optional): 从哪个端口号开始创建。默认是1024开始。
        """
        self.base = base
    
    def next(self):
        """返回下个生成的端口号

        Returns:
            int: 端口号
        """

        port = self.base
        self.base = self.base + 1
        
        return port

def group_mac(ip):
    """根据给定的组播IP地址，返回其对应的组播MAC地址

    Args:
        ip (str): 组播IP地址

    Returns:
        str: 组播MAC地址
    """
    validate_type('ip', ip, str)


    ipExp = re.compile('(\d{1,3}).(\d{1,3}).(\d{1,3}).(\d{1,3})')

    # 验证IP地址格式
    match = ipExp.match(ip)
    assert match != None, '无效的IP地址格式: %s' % ip

    # 将IP转换为32个单位长度的01字符串
    a, b, c, d = match.groups()
    a, b, c, d = int(a), int(b), int(c), int(d)
    strBinary = bin(((a << 8 | b ) << 8 | c) << 8 | d)[2:]
    
    # 验证是否为合法的组播地址
    assert strBinary[0:4] == '1110', '组播IP地址应该以1110开头，但给定的IP为%s开头' % strBinary[0:4]

    # 转换为01字符串格式的MAC组播地址
    strMac = '00000001' + '00000000' + '01011110' + '0' + strBinary[9:]

    # 转换为00:00:00:00:00:00格式的MAC地址
    a, b, c, d, e, f = int(strMac[0:8], 2), int(strMac[8:16], 2), int(strMac[16:24], 2), int(strMac[24:32], 2), int(strMac[32:40], 2), int(strMac[40:48], 2)
    strHexMax = '%02x:%02x:%02x:%02x:%02x:%02x' % (a, b, c, d, e, f)
    
    return strHexMax

def len_of_mask(mask):
    """计算子网掩码对应的长度

    Args:
        mask (str): 点分格式的子网掩码

    Return:
        int: 子网掩码对应的长度，如,255.255.255.0，对应的长度是24
    """
    maskExpr = re.compile('(\d{1,3}).(\d{1,3}).(\d{1,3}).(\d{1,3})')
    match = maskExpr.match(mask)
    a, b, c, d = match.groups()
    a, b, c, d = int(a), int(b), int(c), int(d)
    strBinary = bin(((a << 8 | b ) << 8 | c) << 8 | d)[2:]

    length = 0
    zero = False
    for i in strBinary:
        if i == '1' and zero == False:
            length = length + 1
        
        if i == '1' and zero == True:
            raise RuntimeWarning('非法的子网掩码: %s' % strBinary)
        
        if i == '0':
            zero = True

    return length

def varname(var):
    """获取变量名字符串。如，varname(hello)，将会返回'hello'

    Args:
        var (any): 变量

    Returns:
        str: 变量的名称
    """
    for fi in reversed(inspect.stack()):
        names = [var_name for var_name, var_val in fi.frame.f_locals.items() if var_val is var]
        if len(names) > 0:
            return names[0]

def find_class(className, moduleName, caseSensitive=False):
    """在模块中查找对应的类

    Args:
        className (str): 类名
        moduleName (str): 模块名

    Returns:
        any: 属性对象
    """
    # 导入模块
    module = __import__(moduleName)

    foundClassName = None
    attrList = dir(module)
    for attrName in attrList:
        if not caseSensitive:
            if attrName.lower() == className.lower():
                foundClassName = attrList[attrList.index(attrName)]
                break
        else:
            if attrName == className:
                foundClassName = attrList[attrList.index(attrName)]
                break
    
    return getattr(module, foundClassName, None)

def remove_duplicate_data_from_dic_list(dictList):
    """将字典列表里面的重复项移除

    Args:
        dictList(list): 字典列表
    
    Returns:
        list: 去重后的字典列表
    """

    return [ dict(t) for t in set([tuple(d.items()) for d in dictList]) ]

def md5sum(file_path):
    """计算文件的md5sum。

    Args:
        file_path (str): 文件的路径
    """
    assert os.path.exists(file_path), "指定的文件不存在: %s" % file_path
    
    md5Digest = md5()
    with open(file_path, 'rb') as f:
        while True:
            bytes = f.read()
            if len(bytes) != 0:
                md5Digest.update(bytes)
            else:
                break
    return md5Digest.hexdigest()

def run_by_thread_pool(func, argList, poolSize=5):
    """使用线程池的方法运行函数

    Args:
        func (functionType): 要执行的函数，它接收的参数来自argList中的元素。
        argList (list): 参数列表
        poolSize (int, optional): 线程池大小。默认5。
    """
    pool = threadpool.ThreadPool(5)

    requests = threadpool.makeRequests(func, argList)
    [pool.putRequest(req) for req in requests]
    pool.wait() 

def next_temp_name():
    """创建一个随机字符串

    Returns:
        str: 随机字符串
    """
    return next(tempfile._get_candidate_names())

def random_pick_dict(dictData, count):
    """从可枚举值里面随机取指定数目的项

    Args:
        dictData (dict): 字典对象
        count (int): 取指定数目的项目
    
    Returns:
        dict: 返回处理后的字典(不会修改原字典)
    """
    validate_type('dictData', dictData, dict)

    ret = dictData.copy()

    if len(ret.keys()) < count:
        raise RuntimeError('字典数据不足，无法挑选')

    while True:
        removeCount = len(ret.keys()) - count
        if removeCount == 0:
            break

        toRemoveKey = [ ]
        for key in ret.keys():
            if removeCount == 0:
                break
            if random.randint(0, 1) == 0:
                continue
            else:
                toRemoveKey.append(key)
                removeCount = removeCount - 1
 
        for key in toRemoveKey:
            del ret[key]
    
    return ret

def shift_one_char(data, baseIndex=0):
    """将str中的某一位变换一下

    Args:
        data (str): 要变换的数据
        baseIndex(int): 从哪个index之后开始变换。默认为0。
    Returns:
        str: 变换后的字符串
    """
    validate_type('data', data, str)

    index = random.randint(baseIndex, len(data)-1)
    dataList = list(data)

    alphabet_regex = re.compile('[a-zA-Z]')
    digital_regex = re.compile('[0-9]')

    if alphabet_regex.match(dataList[index]):
        dataList[index] = chr(ord(dataList[index]) + 1)
    
    if digital_regex.match(dataList[index]):
        dataList[index] = "%s" % ((int(dataList[index]) + 1) % 10)
    
    return ''.join(dataList)

def strip_dict_key_and_value(dict_data):
    """将字典中key的空格和value的空格都干掉

    Args:
        dict_data (dict): 要处理的字典

    Returns:
        dict: 处理过后的字典
    """
    ret = { }
    for key in dict_data.keys():
        ret[key.strip()] = dict_data[key].strip() if dict_data[key].strip() != '' else None
    
    return ret

def read_dict_list_from_csv(match_pattern, search_base='.'):
    """从CSV文件里面读取字典，并自动去重

    Args:
        match_pattern (str): 搜索文件名、匹配模式
        search_base (str): 搜索的起始目录
    
    Returns:
        list: 字典列表    
    """
    validate_type('match_pattern', match_pattern, str)
    validate_type('search_base', search_base, str)

    search_dir = pathlib.Path(search_base)

    ret =  [ ]

    for csv_file in search_dir.glob(match_pattern):
        with open(csv_file, 'r') as f:
            rows = csv.DictReader(f)
            for row in rows:
                ret.append(strip_dict_key_and_value(row))
    
    return [dict(t) for t in set([tuple(d.items()) for d in ret])]

def read_str_list_from_txt(match_pattern, search_base='.'):
    """从文本里面读取字符串列表

    Args:
        match_pattern (str): 搜索文件名、匹配模式
        search_base (str): 搜索的起始目录

    Returns:
        list: 去重，去掉空格的字符串列表
    """
    validate_type('match_pattern', match_pattern, str)
    validate_type('search_base', search_base, str)

    search_dir = pathlib.Path(search_base)

    ret =  [ ]

    for txt_file in search_dir.glob(match_pattern):
        with open(txt_file, 'r') as f:
            for line in f.readlines():
                line = line.strip()
                if line != '':
                    ret.append(line)

    ret = list(set(ret))
    ret.sort()
    
    return ret

class dotdict(dict):
    """dot.notation access to dictionary attributes"""
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

__all__ =[
    'value',
    'validate_type',
    'validate_ip_addr',
    'validate_int_range',
    'validate_key',
    'move',
    'merge',
    'expand_list',
    'break_frame_slot_port',
    'count_packets',
    'get_packets_info',
    'wait_until_no_change',
    'wait_for_true',
    'is_ip_connectable',
    'is_valid_ipv4_addr',
    'dict_to_opt',
    'add_dollar_sign',
    'list_to_str',
    'MAC',
    'IP',
    'Port',
    'group_mac',
    'len_of_mask',
    'varname',
    'find_class',
    'remove_duplicate_data_from_dic_list',
    'md5sum',
    'run_by_thread_pool',
    'next_temp_name',
    'random_pick_dict',
    'shift_one_char',
    'strip_dict_key_and_value',
    'read_dict_list_from_csv',
    'read_str_list_from_txt',
    'dotdict'
]