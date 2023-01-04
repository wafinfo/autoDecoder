import binascii
from typing import Dict, Any

from Crypto.Cipher import AES
from Crypto.Cipher.AES import MODE_CBC
from Crypto.Util.Padding import pad, unpad

from demo.demo_work import DemoPacket
from framework import BaseModel, Packet, Framework


def decrypt(data: bytes) -> bytes:
    handle = AES.new(b"1234567890123456", MODE_CBC, b"3216549870321654")
    return unpad(handle.decrypt(binascii.unhexlify(data)), 16)


def encrypt(data: bytes) -> bytes:
    handle = AES.new(b"1234567890123456", MODE_CBC, b"3216549870321654")
    return binascii.hexlify(handle.encrypt(pad(data, 16)))


class Decrypt(BaseModel):
    def on_request(self, data: Packet) -> Dict[str, Any]:
        """处理请求数据

        :param data: Burp中请求数据
        :return: 修改后的数据
        """
        # data.add_header("Test", "Request")
        # print(f"request:\t{data.body}")
        # data.set_body("request=1")
        if data.url.endswith("/set"):
            args = data.argument
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
        """处理响应数据

        :param data: Burp中响应数据
        :return: 修改后的数据
        """
        # data.add_header("Test", "Response")
        # print(f"response:\t{data.body}")
        # data.set_body("response=1")
        if data.from_int == Packet.FromInt.TOOL_INTRUDER:
            args = data.argument
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
    Framework("server", Decrypt(), DemoPacket).start()


if __name__ == '__main__':
    main()
