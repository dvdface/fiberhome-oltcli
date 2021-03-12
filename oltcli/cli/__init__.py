'''
olt commandline interface
'''


from typing import Union
from oltcli.utils import dotdict
from .common import *
from .an6k_17 import *

class OLTCLI:

    @staticmethod
    def get(olt_dev:dotdict) -> Union[OLTCLI_AN6K_17]:
        """get a olt commandline object according to given olt dev

        Args:
            olt_dev (Device): OLT设备资源

        Returns:
            OLTCLI: 返回OLTCLI类
        """

        if olt_dev.model == 'AN6000-17':
            return OLTCLI_AN6K_17(olt_dev)

        raise RuntimeError('不支持的OLT设备型号')