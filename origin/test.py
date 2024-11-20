from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

app = Flask(__name__)
CORS(app)  # 允许跨域访问

# AES 加解密逻辑
def aes_encrypt(data, key):
    key = key.encode("utf-8").ljust(16)[:16]  # 确保密钥长度为 16 字节
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # 填充数据
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode("utf-8")) + padder.finalize()

    # 加密数据
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(encrypted).decode("utf-8")

def aes_decrypt(data, key):
    key = key.encode("utf-8").ljust(16)[:16]  # 确保密钥长度为 16 字节
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # 解密数据
    decrypted = decryptor.update(base64.b64decode(data)) + decryptor.finalize()

    # 移除填充
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted) + unpadder.finalize()
    return unpadded_data.decode("utf-8")

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        # 从请求中获取 JSON 数据
        data = request.json['data']  # 用户输入的明文
        key = request.json['key']    # 用户输入的密钥
        algorithm = request.json.get('algorithm', 'AES')  # 算法，默认为 AES

        # 根据算法调用加密函数（这里只实现了 AES）
        if algorithm == 'AES':
            result = aes_encrypt(data, key)
        else:
            return jsonify({'error': 'Unsupported algorithm'}), 400

        # 返回加密结果
        return jsonify({'result': result})
    except Exception as e:
        # 如果发生错误，返回错误信息
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json['data']
        key = request.json['key']
        algorithm = request.json.get('algorithm', 'AES')

        if algorithm == 'AES':
            result = aes_decrypt(data, key)
        else:
            return jsonify({'error': 'Unsupported algorithm'}), 400

        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)