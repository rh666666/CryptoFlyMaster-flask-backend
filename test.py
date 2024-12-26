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
#RC4加密
from RC4 import RC4
#SM3加密
from SM3 import SM3
#古典密码
from classic import affine, hill, keyed_sub, playfair, vigenere
#祖冲之密码
from ZUC import ZUC

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
        # 获取前端发送的请求数据
        data = request.json.get('data')  # 明文
        key = request.json.get('key')   # 密钥
        algorithm = request.json.get('algorithm')  # 算法名称
        print(f"Algorithm received: {data}")
        print(f"Algorithm received: {key}")
        print(f"Algorithm received: {algorithm}")

        # 判断算法类型并调用相应加密方法
        if algorithm in ['affine', 'hill', 'keyed_sub', 'playfair', 'vigenere']:
            # 古典密码处理
            if algorithm == 'affine':
                key_a, key_b = map(int, key.split(' '))  # affine 需要两个密钥
                result = affine.encrypt(data, key_a, key_b)
            elif algorithm == 'hill':
                key , a = map(str,key.split('%'))
                key = [[int(num) for num in row.split(' ')] for row in key.split(',')]
                result = hill.encrypt(data, key, a)  # Hill 算法
            elif algorithm == 'keyed_sub':
                result = keyed_sub.encrypt(data, key)
            elif algorithm == 'playfair':
                key, a = map(str , key.split(','))  # palyfair 需要密钥和填充字母
                result = playfair.encrypt(data, key ,a )
            elif algorithm == 'vigenere':
                result = vigenere.encrypt(data, key)
        elif algorithm in ['aes', 'des', 'sm4', 'rc4','zuc']:
            # 对称密码处理
            if algorithm == 'aes':
                data = shuruzhuanhuan_encrypt(data,16)  # 进行格式转换和填充
                key = secret_padding(key)    # 进行密钥填充
                result = ''
                for i in range(0, len(data),32):
                    temp_str1 = data[i:i+32]
                    result_list = AES.Encryption(temp_str1, key) 
                    for i in range(4):
                        for j in range(4):
                            result += result_list[j][i].lstrip("0x").zfill(2)
            elif algorithm == 'des':
                data = shuruzhuanhuan_encrypt(data,8)  # 进行格式转换和填充
                key = secret_padding(key)    # 进行密钥填充
                result = ''
                for i in range(0, len(data),16):
                    temp_str1 = data[i:i+16]
                    result = result + DES.encryption(temp_str1, key) 
            elif algorithm == 'sm4':
                data = shuruzhuanhuan_encrypt(data,16)  # 进行格式转换和填充
                key = secret_padding(key)    # 进行密钥填充
                result = ''
                for i in range(0, len(data),32):
                    temp_str1 = data[i:i+32]
                    result = result + SM4.encryption(temp_str1, key) 
            elif algorithm == 'rc4':
                result = RC4.rc4_encrypt_decrypt(key,data,is_encrypt=True)
            elif algorithm == 'zuc':
                key, iv = map(str , key.split(','))  # zuc 需要密钥和iv
                data =''.join([hex(ord(c))[2:].zfill(2) for c in data])
                zuc = ZUC.ZUC(data, key, iv)
                zuc.encrypt()
                result = zuc.encrypt_stream
        elif algorithm in ['sha1', 'sm3']:
            # 散列算法
            if algorithm == 'sha1':
                data=SHA1.string_to_bitstring(data)
                data=SHA1.add_padding_bits(data)
                result=SHA1.sha_1_encode(data)
            elif algorithm == 'sm3':
                data = SM3.string_to_bitstring(data)
                data = SM3.add_padding_bits(data)
                result = SM3.sm3_encode(data)
        else:
            return jsonify({'error': f'Unsupported algorithm: {algorithm}'}), 400
        
        # 返回加密结果
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        # 获取前端发送的请求数据
        data = request.json.get('data')  # 明文
        key = request.json.get('key')   # 密钥
        algorithm = request.json.get('algorithm')  # 算法名称
        print(f"Algorithm received: {algorithm}")

        # 判断算法类型并调用相应解密方法
        if algorithm in ['affine', 'hill', 'keyed_sub', 'playfair', 'vigenere']:
            # 古典密码处理
            if algorithm == 'affine':
                key_a, key_b = map(int, key.split(' '))  # affine 需要两个密钥
                if not affine.rp(key_a,26):
                    result = '由于key1与26不互素，该密文不可逆！'
                else:
                    result = affine.decrypt(data, key_a, key_b)
            elif algorithm == 'hill':
                key = [[int(num) for num in row.split(' ')] for row in key.split(',')]
                result = hill.decrypt(data, key)  # Hill 算法
            elif algorithm == 'keyed_sub':
                result = keyed_sub.decrypt(data, key)
            elif algorithm == 'playfair':
                key, a = map(str , key.split(','))  # palyfair 需要密钥和填充字母
                result = playfair.decrypt(data, key)
            elif algorithm == 'vigenere':
                result = vigenere.decrypt(data, key)
        elif algorithm in ['aes', 'des', 'sm4', 'rc4','zuc']:
            # 对称密码处理
            if algorithm == 'aes':
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
            elif algorithm == 'des':
                key = secret_padding(key)    # 进行密钥填充
                result = ''
                for i in range(0, len(data),16):
                    temp_str1 = data[i:i+16]
                    result = result + DES.decryption(temp_str1, key)
                data_bytes = bytes.fromhex(result)
                result = pkcs7_unpad(data_bytes).hex()
                byte_data = bytes.fromhex(result)
                result = ''.join(chr(b) for b in byte_data)
            elif algorithm == 'sm4':
                key = secret_padding(key)    # 进行密钥填充
                result = ''
                for i in range(0, len(data),32):
                    temp_str1 = data[i:i+32]
                    result = result + SM4.decryption(temp_str1, key)
                data_bytes = bytes.fromhex(result)
                result = pkcs7_unpad(data_bytes).hex()
                byte_data = bytes.fromhex(result)
                result = ''.join(chr(b) for b in byte_data)
            elif algorithm == 'rc4':
                result = RC4.rc4_encrypt_decrypt(key, data, is_encrypt=False)
            elif algorithm == 'zuc':
                result = 'ZUC密码算法暂未实现解密功能'
        elif algorithm in ['sha1', 'sm3']:
            result = '单向散列算法不支持解密'
        else:
            return jsonify({'error': f'Unsupported algorithm: {algorithm}'}), 400

        # 返回解密结果
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
