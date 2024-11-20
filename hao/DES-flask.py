from hao import DES
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    """
    对数据进行 PKCS#7 填充。
    :param data: 输入的字节数据
    :param block_size: 块大小，默认为 8（DES 的块大小）
    :return: 填充后的字节数据
    """
    padding_len = block_size - len(data) % block_size
    padding = bytes([padding_len] * padding_len)
    return data + padding

def pkcs7_unpad(data: bytes) -> bytes:
    """
    去除 PKCS#7 填充。
    :param data: 填充后的字节数据
    :return: 去填充后的字节数据
    """
    padding_len = data[-1]  # 获取最后一个字节的值
    if padding_len > len(data):
        raise ValueError("Invalid padding.")
    return data[:-padding_len]
'''
def main():
        choice = int(input("请输入 1 进行加密, 2 进行解密: "))
        if choice not in [1, 2]:
            print("无效选择")
            return
        
        Text = input("请输入文本:")
        if choice == 1:
            Text_hex = ''.join(format(ord(char), '02x') for char in Text if char.isprintable())
            data_bytes = bytes.fromhex(Text_hex)
            Text_hex = pkcs7_pad(data_bytes).hex()
        else:
            Text_hex = Text

        Key = input("请输入密钥(64位,8字节):")
        Key_hex = ''.join(format(ord(char), '02x') for char in Key if char.isprintable())
        if len(Key_hex) != 16:
            print("密钥长度不为 64 位。")
            return
        
        result = ''

        for i in range(0, len(Text_hex),16):
            temp_str1 = Text_hex[i:i+16]
            result += DES.encryption(temp_str1, Key_hex) if choice == 1 else DES.decryption(temp_str1, Key_hex)

        if result:
            if choice == 1:
                print("加密后的密文:"+ result)
            else:
                data_bytes = bytes.fromhex(result)
                result = pkcs7_unpad(data_bytes).hex()
                byte_data = bytes.fromhex(result)
                result = ''.join(chr(b) for b in byte_data)
                print("解密后的明文:"+ result)
        else:
            print("处理失败，请检查输入。")
'''
def shuruzhuanhuan_encrypt(Text_hex):
    '''加密时对输入的文本进行格式转换，并进行填充'''
    Text_hex = ''.join(format(ord(char), '02x') for char in Text_hex if char.isprintable())
    data_bytes = bytes.fromhex(Text_hex)
    Text_hex = pkcs7_pad(data_bytes).hex()
    return Text_hex

def secret_padding(key_hex):
    '''对密钥进行填充'''
    key_hex = ''.join(format(ord(char), '02x') for char in key_hex if char.isprintable())
    return key_hex

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        # 从请求中获取 JSON 数据
        data = request.json['data']  # 用户输入的明文
        data = shuruzhuanhuan_encrypt(data)  # 进行格式转换和填充
        key = request.json['key']    # 用户输入的密钥
        key = secret_padding(key)    # 进行密钥填充
        algorithm = request.json.get('algorithm', 'DES')  # 算法，默认为 AES

        # 根据算法调用加密函数（这里只实现了 AES）
        result = ''
        if algorithm == 'DES':
#            result = aes_encrypt(data, key)
            for i in range(0, len(data),16):
                temp_str1 = data[i:i+16]
                result = result + DES.encryption(temp_str1, key) 
        else:
            return jsonify({'error': 'Unsupported algorithm'}), 400

        # 返回加密结果
        return jsonify({'result': result})
    except Exception as e:
        # 如果发生错误，返回错误信息
        result = '请输入八字节的密钥'  # 自定义的错误内容
        return jsonify({'result': result, 'error': str(e)}), 500
#        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json['data']
        key = request.json['key']
        key = secret_padding(key)    # 进行密钥填充
        algorithm = request.json.get('algorithm', 'DES')

        result = ''
        if algorithm == 'DES':
#            result = aes_decrypt(data, key)
            for i in range(0, len(data),16):
                temp_str1 = data[i:i+16]
                result = result + DES.decryption(temp_str1, key)
            data_bytes = bytes.fromhex(result)
            result = pkcs7_unpad(data_bytes).hex()
            byte_data = bytes.fromhex(result)
            result = ''.join(chr(b) for b in byte_data)

        else:
            return jsonify({'error': 'Unsupported algorithm'}), 400

        return jsonify({'result': result})
    except Exception as e:
        result = '请输入正确格式的密文'  # 自定义的错误内容
        return jsonify({'result': result, 'error': str(e)}), 500
#        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)


'''if __name__ == '__main__':
    main()
    input("按任意键退出...")
'''