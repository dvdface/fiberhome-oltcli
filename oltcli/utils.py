import re
from typing import Any, NoReturn, Optional, Type, List
from types import FunctionType
from dateutil.parser import parse
import threadpool


def run_by_thread_pool(func:FunctionType, argList:List, poolSize:int=5) -> NoReturn:
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

def auto_convert(value:str, max_value:Optional[int]=None) -> Any:
    """将字符串类型表示的值尽可能的转换成对应格式的类型。如，'1.0'转换成浮点型，'1'或'0xFF'转换成整型。

    Args:
        value (str or None): 要转换的字符串格式的值，为None时不转换，直接返回。
        max_value (int, optional): 当指定该参数时，如果转换的int类型的值为maxValue将会返回'null'。如，指定65535，当值strValue为'65535'时，自动转换为'null'，而非整数。 默认为None，不进行判定和转换。

    Returns:
        any: 转换后的值，'1'将为int类型的1， '1.0'将为float类型的1.0， '1920-10-1 10:11:11'转换为datetime格式，'hello'仍然为'hello'
    """
    # 如果为None不做转换
    if value == None:
        return value

    # 去掉首尾空格
    value = value.strip()
    
    intExp = re.compile('^-?(0x|0X)?\d+$') # 匹配 10和16进制的±整数
    floatExp = re.compile('^-?\d+.\d+$') # 匹配 10进制的±浮点数
    datetimeExp = re.compile("\d{4,4}-\d{1,2}-\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}")

    if intExp.match(value):
        # 如果是整数类型
        intValue = int(value, 10 if value.find('0x') == -1 and  value.find('0x') == -1 else 16)
        if max_value != None and intValue == max_value:
            # 当设置了达到最大值的选项，且满足时，返回'null'
            return 'null'
        else:
            return intValue
    elif floatExp.match(value):
        # 如果是浮点类型
        return float(value)
    elif datetimeExp.match(value):
        # 如果是日期类型
        if value != '0000-00-00 00:00:00':
            return parse(value)
        else:
            return None
    else:
        # 不识别字符串的不处理
        return value


def len_of_mask(mask:str) -> int:
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

def validate_key(name:str, expected_key:str, expected_type:Type) -> NoReturn:
    """验证字典是否包含指定类型的key

    Args:
        name (dict): 要进行检查的字典
        expected_key (Any): 要进行检查的键名
        expected_type (Any或list): 要确认键值的类型
    """
    assert expected_key in name.keys(), "字典中不包含该键：%s" % expected_key

    if type(expected_type) != list:

        assert type(name[expected_key]) == expected_type, "字典中该键值的类型不符合预期，预期%s，实际%s" % (expected_type, type(name[expected_key]))
    else:
        assert type(name[expected_key]) in expected_type, "字典中该键值的类型不符合预期，预期%s，实际%s" % (expected_type, type(name[expected_key]))

def list_to_str(arg:List, template:Optional[str]='%s', sep:Optional[str]=' ') -> str:
    """将给定的列表中元素，依次使用模板格式化后，使用指定的分隔符连接为一个长串后返回。如，list2Str([1,2,3], '$%s')返回'$1 $2 $3'

    Args:
        arg (list): 要处理的列表
        template (str): 用于格式化的模板。默认值'%s'。
    Returns:
        str: 返回的字符长串
    """
    ret = ''
    for i in arg:
        ret = ret + sep + template % i
    return  ret.strip()