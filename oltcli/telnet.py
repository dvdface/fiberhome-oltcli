from abc import ABC, abstractmethod
from typing import NoReturn

from telnetlib import Telnet
import logging

logger = logging.getLogger(__name__)

class Connection(ABC):
    """Connection Class
    
    Connection represents a connection with OLT
    """
    def __enter__(self):
        """to support with syntax
        """
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        """to support with syntax
        """
        self.disconnect()

    @abstractmethod
    def connect(self) -> NoReturn:
        """called when connect
        """
        pass

    @abstractmethod
    def disconnect(self) -> NoReturn:
        """called when disconnect
        """
        pass

    @abstractmethod
    def run(self, cmd:str, **kwargs) -> str:
        """called when run command through connection

        Args:
            cmd (str): command to run
        
        Returns:
            str: result in str
        """
        pass

    def __del__(self):
        """disconnect when free
        """
        self.disconnect()

class OLTTelnet(Connection):
    """OLT Telnet

    OLTTelnet represents a telnet connection with OLT
    """

    def __init__(self, ip:str, username:str, password:str, read_interval:int=1) -> NoReturn:
        """init

        Args:
            ip (str): OLT ip address
            username (str): username for connection
            password (str): password for connection
        """
        # save information need for connection
        self._ip = ip
        self._username = username
        self._password = password

        # save read interval
        self._read_interval = read_interval

        # telnet client
        self._telnet = None

    def connect(self):
        """connect OLT with given information
        """
        # close already opened telnet first
        if self._telnet != None:
            self._telnet.close()
            self._telnet = None

        # connect telnet server
        self._telnet = Telnet(self._ip, 23)

        self._login()
        self._admin()

        # disable paging
        self.run('terminal length 0')

    def _admin(self):
        """enter admin mode
        """
        assert self._telnet != None

        # input en
        self._telnet.read_until(b"User>", self._read_interval).decode("ascii")
        self._telnet.write("enable".encode('ascii') + b"\n")

        # input password
        self._telnet.read_until(b"Password:", self._read_interval)
        self._telnet.write(self._password.encode('ascii') + b"\n")

    def _login(self):
        """login
        """
        assert self._telnet != None

        # input username
        self._telnet.read_until(b"Login:", self._read_interval)
        self._telnet.write(self._username.encode('ascii') + b"\n")

        # input password
        self._telnet.read_until(b"Password:", self._read_interval)
        self._telnet.write(self._password.encode('ascii') + b"\n")

    def disconnect(self):
        """disconnect with OLT
        """
        if(self._telnet != None):
            self._telnet.close()
            self._telnet = None

    def run(self, cmd:str, append_return:bool=True, sepcial_end_mode:bool=False) -> str:
        """run command through telnet connection

        Args:
            cmd (str): command need to run
            append_return (bool, optional): whether add RETURN at end of command, default is True
            sepcial_end_mode (bool, optional): whether use a special way to end reading result, default is False

        Returns:
            str: result to return
        """
        if(self._telnet == None):
            raise RuntimeError("need connect OLT first")

        # before run command, should read out last result in buffer
        self._telnet.read_until(b"# ", self._read_interval).decode("ascii")

        # run command
        if append_return:
            cmdBytes = cmd.encode('ascii') + b"\r\n"
        else:
            cmdBytes = cmd.encode('ascii')
        self._telnet.write(cmdBytes)

        # read result
        output_data = [ ]
        while(True):
            
            # read in every interval
            data = self._telnet.read_until(b"# ", self._read_interval).decode("ascii")
            output_data.append(data)
            
            # if read end symbols, break
            if("# " in data \
                or "User> " in data \
                or "Login: " in data \
                or "Password: " in data):
                break

        raw_output = "".join(output_data)
        output = raw_output.split("\r\n")[1:-1]
        ret = "\r\n".join(output)
        logger.debug(ret)

        return ret

__all__ = [

    'Connection',
    'OLTTelnet'
]

