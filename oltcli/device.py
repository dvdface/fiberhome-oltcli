'''
OLT设备池
'''


from devicepool import DevicePool

from .utils import read_dict_list_from_csv

olt_list = read_dict_list_from_csv('**/olt_list.csv')

olt_pool = DevicePool(olt_list)


__all__ = [

    'olt_pool'
]

if __name__ == "__main__":
    print(olt_list)