import binascii
import json
from typing import Dict, Any

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from framework import BaseModel, Packet, Framework, Argument


class DemoPacket(Packet):
    def create_argument(self, data: str):
        self._argument = DemoArgument(self._argument_name, data)


class DemoArgument(Argument):
    def __init__(self, name: str, data: str):
        self.__data: dict = {}
        self.__skip = False
        try:
            self.__data = json.loads(data)
            self.__skip = self.__data["skip"]
        except (KeyError, TypeError):
            pass
        super().__init__(name, self.__data)

    def add_argument(self, name: str, value):
        self.__data[name] = value

    def remove_argument(self, name: str):
        self.__data.pop(name)

    def clear(self):
        self.__data.clear()

    def transform(self):
        if len(self.__data) == 0:
            return None
        return json.dumps(self.__data)

    @property
    def skip(self):
        return self.__skip


KEY = b"1234567890123456"
IV = b"3216549870321654"
PAD_SIZE = 16


def decrypt(data: bytes):
    handle = AES.new(KEY, AES.MODE_CBC, IV)
    return unpad(handle.decrypt(binascii.unhexlify(data)), PAD_SIZE)


def encrypt(data: bytes):
    handle = AES.new(KEY, AES.MODE_CBC, IV)
    return binascii.hexlify(handle.encrypt(pad(data, PAD_SIZE)))


class Demo(BaseModel):
    def on_request(self, data: Packet) -> Dict[str, Any]:
        if data.url.endswith(":60000/set"):
            args: DemoArgument = data.argument
            if data.from_int == Packet.FromInt.EDITOR:
                if not args.skip:
                    data.set_body(decrypt(data.body))
                    args.add_argument("skip", True)
                else:
                    data.set_body(encrypt(data.body))
                    args.remove_argument("skip")
            else:
                if args.skip:
                    data.set_body(encrypt(data.body))
                args.clear()
        return data.to_data()

    def on_response(self, data: Packet) -> Dict[str, Any]:
        if data.from_int == Packet.FromInt.EDITOR:
            args: DemoArgument = data.argument
            if not args.skip:
                try:
                    data.set_body(decrypt(data.body))
                    args.add_argument("skip", True)
                except (binascii.Error, ValueError):
                    pass
            else:
                data.set_body(encrypt(data.body))
                args.remove_argument("skip")
        return data.to_data()


def main():
    Framework("Demo", Demo(), DemoPacket).start("0.0.0.0", 5000)
