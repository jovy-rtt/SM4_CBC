'''
Author:     jovy-rtt
Date:       2020/4/4
Version:    1.0
Function:   SM4_CBC
'''
import os
import pickle
import hashlib
import binascii

# 测试对象：
# 明文：0x0123456789abcdeffedcba9876543210
# 密匙：0x0123456789abcdeffedcba9876543210 
# 密文：0x681edf34d206965e86b3e94f536e4246
'''
首先从Data.pkl文件中读入S盒，系统参数FK，固定CK常数
'''
with open('Data.pkl','rb') as f:
    global DATA
    DATA=pickle.load(f)
    f.close()
S_BOX = DATA[0]#S盒是字典类型
FK = DATA[1]#FK参数是元组类型
CK = DATA[2]#CK参数是元组类型

#int转为指定长度的十六进制的字符串，不足补0，返回串无'0x'
def Num_hex(num,width=1):
    return '{:0>{width}x}'.format(num,width=width)

#循环左移，输入int,输出int
def Left(x,num):
    a=x>>(32-num)
    b=x & eval('0b'+num*'0'+(32-num)*'1')
    return a+(b<<num)

#数据处理,输入一个int，输出一个四元素列表,ln为规定的十六进制长度，默认为8
def ChangeD0(num,ln=8):
    st=Num_hex(num,ln)
    L=[]
    for i in range(0,ln,ln//4):
        L.append(eval('0x'+st[i:i+(ln//4)]))
    return L

#数据处理，输入一个四元素列表，输出一个int
def ChangeD1(L,ln=8):
    st='0x'
    for i in range(4):
        st+=str(Num_hex(L[i],ln//4))
    return eval(st)

#B变换，传入一个长度为四的列表类型，输出一个长度为4的列表  单位32
def B_T(bits):
    g=lambda x: S_BOX.get(x)
    return [g(bits[i]) for i in range(4)]

#L变换，输入一个int类型的B，输出是一个int类型的值   
def L_T(B):
    return B ^ Left(B,2) ^ Left(B,10) ^ Left(B,18) ^ Left(B,24)

#T合成变化,输入一个int,输出一个int
def T_T(bits):
    return L_T(ChangeD1(B_T(ChangeD0(bits))))

#轮函数F,输入一个四个元素-32位的L，一个rk，输出一个int-32位
def F(L,rk):
    return L[0] ^ T_T(L[1] ^ L[2] ^ L[3] ^ rk)

#RK_L变换，输入一个int类型的B，输出是一个int类型的值   
def RK_L_T(B):
    return B ^ Left(B,13) ^ Left(B,23)

#RK_T合成变化,输入一个int,输出一个int
def RK_T_T(bits):
    return RK_L_T(ChangeD1(B_T(ChangeD0(bits))))

#RK扩展函数,轮密匙产生函数,输入为int
def RK_E(MK):
    MK_L=ChangeD0(MK,32)
    K=[MK_L[0]^FK[0],MK_L[1]^FK[1],MK_L[2]^FK[2],MK_L[3]^FK[3]]
    global RK
    RK=[]
    for i in range(0,32):
        tmp=(K[i] ^RK_T_T(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]))
        K.append(tmp)
        RK.append(tmp)

#加密函数，输入int-128位，输出密文int类型
def encrypt(bits,mk):
    RK_E(mk)
    Plaintext=ChangeD0(bits,32)
    for i in range(32):
        Plaintext.append(F(Plaintext[i:i+4],RK[i]))
    return eval('0x{0:0>8x}{1:0>8x}{2:0>8x}{3:0>8x}'.format(Plaintext[35],Plaintext[34],Plaintext[33],Plaintext[32]))

#解密函数，输入int-128位，输出明文int类型
def decrypt(bits,mk):
    RK_E(mk)
    global RK
    RK=RK[::-1] #这里是与加密不同的唯一点
    Plaintext=ChangeD0(bits,32)
    for i in range(32):
        Plaintext.append(F(Plaintext[i:i+4],RK[i]))
    return eval('0x{0:0>8x}{1:0>8x}{2:0>8x}{3:0>8x}'.format(Plaintext[35],Plaintext[34],Plaintext[33],Plaintext[32]))

#对于cbc模式的加密，输入明文和密匙，字符串模式,输出密文str
def encrypt_cbc(Plaintext,Key):

    #首先处理一下密文，根据md5加密特性，选择md5处理
    Key_md=hashlib.md5(Key.encode(encoding='utf-8')).hexdigest()
    mk=eval('0x'+Key_md)#mk便是符合条件的密匙

    #对于明文的处理，处理结果为不带0x的十六进制字节数组
    Plaintext_bytes=binascii.hexlify(bytes(Plaintext.encode('utf-8')))
    Plaintext_str = str(Plaintext_bytes)[2:-1]
    
    vi=mk #初始变量这里等于密匙了，也可以自定义

    #对于明文的填充
    if len(Plaintext_str)%32!=0:
        Plaintext_str+='0'*(32-len(Plaintext_str)%32)

    Ciphertext=''#密文
    for i in range(0,len(Plaintext_str),32):
        tmp=eval('0x'+Plaintext_str[i:i+32])^vi
        res=encrypt(tmp,mk)
        Ciphertext+=Num_hex(res,32)
        vi=res
    return Ciphertext

#对于cbc模式的解密，输入密文和密匙，字符串模式,输出明文str
def decrypt_cbc(Ciphertext,Key):
    #同上
    Key_md=hashlib.md5(Key.encode(encoding='utf-8')).hexdigest()
    mk=eval('0x'+Key_md)
    vi=mk
    Plaintext_str=''#明文
    if len(Ciphertext)%32 != 0 :
        print('这不是一个规范的密文！！！')
        os._exit(0) 
    for i in range(0,len(Ciphertext),32):
        tmp=eval('0x'+Ciphertext[i:i+32])#这里异或的位置改变了，参考cbc模式
        res=decrypt(tmp,mk)^vi
        Plaintext_str+=Num_hex(res,32)
        vi=tmp
    Plaintext_bytes=eval("b'"+Plaintext_str+"'")
    Plaintext=binascii.unhexlify(Plaintext_bytes).decode('utf-8')
    return Plaintext

if __name__ == '__main__':
    print('--------SM4_CBC模式加密/解密------')
    m=input('请输入要加密的明文：')
    k=input('请输入加密密匙：')
    c=encrypt_cbc(m,k)
    print('加密后的密文为：'+c)
    Plaintext=decrypt_cbc(c,k)
    print('经过解密后为：'+Plaintext)
