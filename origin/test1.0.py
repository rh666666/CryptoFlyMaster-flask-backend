#flask项目
from flask import Flask, request, jsonify
from flask_cors import CORS
#DES加密
from DES import DES
#AES加密
from AES import AES
#SM4加密
from SM4 import SM4
#SHA-1加密
from SHA1 import SHA1

app = Flask(__name__)
CORS(app)  # 允许跨域访问

#AES、DES对明文的预处理
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

def shuruzhuanhuan_encrypt(Text_hex,i):
    '''加密时对输入的文本进行格式转换，并进行填充'''
    Text_hex = ''.join(format(ord(char), '02x') for char in Text_hex if char.isprintable())
    data_bytes = bytes.fromhex(Text_hex)
    Text_hex = pkcs7_pad(data_bytes,i).hex()
    return Text_hex

def secret_padding(key_hex):
    '''对密钥进行填充'''
    key_hex = ''.join(format(ord(char), '02x') for char in key_hex if char.isprintable())
    return key_hex

#前后端交互
@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        # 从请求中获取 JSON 数据
        data = request.json['data']  # 用户输入的明文
        key = request.json['key']    # 用户输入的密钥
        algorithm = request.json.get('algorithm', 'AES')  # 算法，默认为 AES
#        print(f"Algorithm received: {algorithm}")

        # 根据算法调用加密函数（这里只实现了 AES，DES）
        if algorithm == 'AES':
            data = shuruzhuanhuan_encrypt(data,16)  # 进行格式转换和填充
            key = secret_padding(key)    # 进行密钥填充
            result = ''
            for i in range(0, len(data),32):
                temp_str1 = data[i:i+32]
                result_list = AES.Encryption(temp_str1, key) 
                for i in range(4):
                    for j in range(4):
                        result += result_list[j][i].lstrip("0x").zfill(2)

        elif algorithm == 'DES':
            data = shuruzhuanhuan_encrypt(data,8)  # 进行格式转换和填充
            key = secret_padding(key)    # 进行密钥填充

            result = ''
            for i in range(0, len(data),16):
                temp_str1 = data[i:i+16]
                result = result + DES.encryption(temp_str1, key) 
        
        elif algorithm == 'SM4':
            data = shuruzhuanhuan_encrypt(data,16)  # 进行格式转换和填充
            key = secret_padding(key)    # 进行密钥填充

            result = ''
            for i in range(0, len(data),32):
                temp_str1 = data[i:i+32]
                result = result + SM4.encryption(temp_str1, key) 

        elif algorithm == 'SHA-1':
            bitstring = SHA1.string_to_bitstring(data)
            bitstring_hex = SHA1.add_padding_bits(bitstring)
            result=SHA1.sha_1_encode(bitstring_hex)
        else:    
            return jsonify({'error': 'Unsupported algorithm'}), 400
        
        # 返回加密结果
        return jsonify({'result': result})
    except Exception as e:
        # 如果发生错误，返回错误信息
        if algorithm == 'AES':
            result = '请输入16字节的密钥,采用utf-8编码'  # 自定义的错误内容
            return jsonify({'result': result, 'error': str(e)}), 500
        elif algorithm == 'DES':
            result = '请输入8字节的密钥,采用utf-8编码'  # 自定义的错误内容
            return jsonify({'result': result, 'error': str(e)}), 500
        elif algorithm == 'SM4':
            result = '请输入16字节的密钥,采用utf-8编码'  # 自定义的错误内容
            return jsonify({'result': result, 'error': str(e)}), 500
        elif algorithm == 'SHA-1':
            result = '请输入需要加密的字符串'  # 自定义的错误内容
        else:
            return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json['data']
        key = request.json['key']
        algorithm = request.json.get('algorithm', 'AES')

        if algorithm == 'AES':
            key = secret_padding(key)    # 进行密钥编码
            
            result = ''
            for i in range(0, len(data),32):
                temp_str1 = data[i:i+32]
                result_list = AES.Decryption(temp_str1, key)
                for i in range(4):
                    for j in range(4):
                        result += result_list[j][i].lstrip("0x").zfill(2)
            data_bytes = bytes.fromhex(result)
            result = pkcs7_unpad(data_bytes).hex()
            byte_data = bytes.fromhex(result)
            result = ''.join(chr(b) for b in byte_data)

        elif algorithm == 'DES':
            key = secret_padding(key)    # 进行密钥填充
            
            result = ''
            for i in range(0, len(data),16):
                temp_str1 = data[i:i+16]
                result = result + DES.decryption(temp_str1, key)
            data_bytes = bytes.fromhex(result)
            result = pkcs7_unpad(data_bytes).hex()
            byte_data = bytes.fromhex(result)
            result = ''.join(chr(b) for b in byte_data)

        elif algorithm == 'SM4':
            key = secret_padding(key)    # 进行密钥填充
            
            result = ''
            for i in range(0, len(data),32):
                temp_str1 = data[i:i+32]
                result = result + SM4.decryption(temp_str1, key)
            data_bytes = bytes.fromhex(result)
            result = pkcs7_unpad(data_bytes).hex()
            byte_data = bytes.fromhex(result)
            result = ''.join(chr(b) for b in byte_data)
        elif algorithm == 'SHA-1':
            return jsonify({'error': '无法解密SHA1'}), 400
        else:
            return jsonify({'error': 'Unsupported algorithm'}), 400

        return jsonify({'result': result})
    except Exception as e:
        if algorithm == 'AES':
            result = '请输入16字节的密钥,采用utf-8编码'  # 自定义的错误内容
            return jsonify({'result': result, 'error': str(e)}), 500
        elif algorithm == 'DES':
            result = '请输入8字节的密钥,采用utf-8编码'  # 自定义的错误内容
            return jsonify({'result': result, 'error': str(e)}), 500
        else:
            return jsonify({'error': str(e)}), 500
#        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
