import binascii

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request, send_file

app = Flask("demo")

KEY = b"1234567890123456"
IV = b"3216549870321654"
PAD_SIZE = 16


def encrypt(data: bytes) -> bytes:
    handle = AES.new(KEY, AES.MODE_CBC, IV)
    return binascii.hexlify(handle.encrypt(pad(data, PAD_SIZE)))


def decrypt(data: bytes) -> bytes:
    handle = AES.new(KEY, AES.MODE_CBC, IV)
    return unpad(handle.decrypt(binascii.unhexlify(data)), PAD_SIZE)


global_data = "from server"


@app.after_request
def cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


@app.route("/get", methods=["GET"])
def get():
    return encrypt(global_data.encode()).decode()


@app.route("/set", methods=["POST"])
def set_value():
    global global_data
    global_data = decrypt(request.data).decode()
    return encrypt((global_data + "ok").encode()).decode()


@app.route("/aes.js", methods=["GET"])
def get_js():
    return send_file("aes.js")


@app.route("/", methods=["GET"])
def main():
    return send_file("main.html")


if __name__ == '__main__':
    app.run("0.0.0.0", 60000)
