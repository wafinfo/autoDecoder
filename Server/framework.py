import base64
import json
from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Any, List, Optional

from flask import Flask, request

from util import make_response


class Argument(object):
    """以数据包为单位封装插件参数"""

    def __init__(self, name: str, data):
        self.__name = name
        self.__data = data

    @abstractmethod
    def add_argument(self, name: str, value):
        """需子类实现

        :param name: 参数名称
        :param value: 参数内容
        """
        raise NotImplemented

    @abstractmethod
    def remove_argument(self, name: str):
        """需子类实现

        :param name: 参数名称
        """
        raise NotImplemented

    def transform(self):
        """子类重写，实现自定义数据序列化为字符串保存

        :return: 序列化字符串(None为清除参数)
        """
        return self.__data

    def clear(self):
        """子类重写，实现自定义数据清除（Burp发送数据包前清除）

        """
        self.__data = None

    def write_out(self, packet: "Packet"):
        if self.__name is None:
            return
        tmp = self.transform()
        if tmp is None:
            packet.remove_header(self.__name)
        else:
            packet.add_header(self.__name, tmp)


class Packet(object):
    """Burp数据包封装"""

    class Type(Enum):
        """数据包类型"""
        REQUEST = 0
        RESPONSE = 1

    class FromInt(Enum):
        """数据包来源"""
        TOOL_PROXY = 0x00000004
        TOOL_INTRUDER = 0x00000020
        TOOL_REPEATER = 0x00000040
        TOOL_EXTENDER = 0x00000400
        EDITOR = 0x00000800

    def __init__(self, _type: Type, from_int: FromInt, url: str, order: List[str],
                 headers: Dict[str, str], argument_name: str, body: str):
        """构建数据包

        :param _type: 类型
        :param from_int: 来源
        :param url: 请求URL，type为RESPONSE时为空
        :param order: Header顺序
        :param headers: Header头数据
        :param argument_name: 插件使用的参数名称
        :param body: Base64编码的Body数据
        """
        self.__type = _type
        self.__from_int = from_int
        self.__url = url
        self.__order = order
        self.__headers = headers
        self._argument = None
        self._argument_name = argument_name
        tmp = None
        try:
            tmp = headers[argument_name]
            self.__headers.pop(argument_name)
        except KeyError:
            pass
        self.create_argument(tmp)
        self.__body = base64.b64decode(body)
        self.__header_modified = False

    def create_argument(self, data: str):
        """子类重写，实现自定义参数构造

        :param data:
        """
        self._argument = Argument(self._argument_name, data)

    @property
    def type(self) -> Type:
        return self.__type

    @property
    def from_int(self) -> FromInt:
        return self.__from_int

    @property
    def url(self) -> Optional[str]:
        """当from_int为EDITOR时，Request可能会丢失"http"、"https"字符串部分，Response为None。
        建议使用endswith匹配

        :return: 数据包请求URL地址
        """
        return self.__url

    @property
    def headers(self) -> Dict[str, str]:
        return self.__headers

    @property
    def body(self) -> bytes:
        return self.__body

    def set_body(self, body: bytes):
        self.__body = body

    def remove_header(self, name: str):
        try:
            self.__order.remove(name)
            self.__headers.pop(name)
        except (ValueError, KeyError):
            pass
        self.__header_modified = True

    def add_header(self, name: str, value: str):
        if value is None:
            return
        if name not in self.__order:
            self.__order.append(name)
        self.__headers[name] = value
        self.__header_modified = True

    @property
    def argument(self):
        return self._argument

    def to_data(self) -> Dict[str, Any]:
        """数据返回前解封装

        :return: json数据
        """
        if self._argument is not None:
            self._argument.write_out(self)
        return make_response(base64.b64encode(self.__body).decode(),
                             self.__order if self.__header_modified else None,
                             self.__headers if self.__header_modified else None)


def create_packet(js: dict, impl):
    """构建数据包

    :param js: 插件发送的json数据
    :param impl: 反序列化类
    :return: Packet对象
    """
    from_int = js["from"]
    if from_int == Packet.FromInt.TOOL_PROXY.value:
        from_int = Packet.FromInt.TOOL_PROXY
    elif from_int == Packet.FromInt.TOOL_INTRUDER.value:
        from_int = Packet.FromInt.TOOL_INTRUDER
    elif from_int == Packet.FromInt.TOOL_REPEATER.value:
        from_int = Packet.FromInt.TOOL_REPEATER
    elif from_int == Packet.FromInt.TOOL_EXTENDER.value:
        from_int = Packet.FromInt.TOOL_EXTENDER
    elif from_int == Packet.FromInt.EDITOR.value:
        from_int = Packet.FromInt.EDITOR
    return impl(Packet.Type.REQUEST if js["type"] == Packet.Type.REQUEST.value else Packet.Type.RESPONSE,
                from_int, js["url"] if "url" in js else None, js["order"], js["headers"], js["flag"], js["body"])


class BaseModel(ABC):
    """模型接口"""

    @abstractmethod
    def on_request(self, data: Packet) -> Dict[str, Any]:
        return data.to_data()

    @abstractmethod
    def on_response(self, data: Packet) -> Dict[str, Any]:
        return data.to_data()


class Framework(object):
    """基础框架"""

    def __init__(self, name: str, do_obj, packet_impl=Packet, url_path="/do"):
        """

        :param name: Flask名称
        :param do_obj: 数据包处理实现对象
        :param packet_impl: 数据包反序列化类
        :param url_path: Flask绑定URL
        """
        self.__app = Flask(name)

        @self.__app.route(url_path, methods=["POST"])
        def do_work():
            if not request.is_json:
                return json.dumps({})
            packet = create_packet(request.json, packet_impl)
            # print(f"Request:{packet.from_int}\n{json.dumps(request.json)}")
            result = None
            if packet.type == Packet.Type.REQUEST:
                try:
                    result = do_obj.on_request(packet)
                except Exception as e:
                    print(e)
                    result = BaseModel.on_request(do_obj, packet)
            elif packet.type == Packet.Type.RESPONSE:
                try:
                    result = do_obj.on_response(packet)
                except Exception as e:
                    print(e)
                    result = BaseModel.on_response(do_obj, packet)
            # print(f"Response:{json.dumps(result)}")
            return json.dumps(result)

    def start(self, address: str = "127.0.0.1", port: int = 5000):
        self.__app.run(address, port)
