
## SM4_CBC
1.是一个用CBC模式实现的SM4密码算法，支持加密解密操作
2.对于密匙的处理，采用了md5算法，所以密匙可以随意输入(也不要太随意)
3.文件加密可以自行加上几行代码就可以
4.时间复杂度没有注意，简单的加密很快，文件什么的应该会挺长的吧

## SM4
国密SM4(无线局域网SMS4)算法， 一个分组算法， 分组长度为128bit， 密钥长度为128bit
具体参考：http://www.oscca.gov.cn/sca/zxfw/bdxz.shtml 国密下载

## 用法:
关于SM4的实现在代码里面，这里就不在多说了


```python
if __name__ == '__main__':
    print('--------SM4_CBC模式加密/解密------')
    m=input('请输入要加密的明文：')
    k=input('请输入加密密匙：')
    c=encrypt_cbc(m,k)
    print('加密后的密文为：'+c)
    Plaintext=decrypt_cbc(c,k)
    print('经过解密后为：'+Plaintext)
```
##### 运行结果
--------SM4_CBC模式加密/解密------
请输入要加密的明文：武汉，加油！中国，加油！！
请输入加密密匙：wuhan,come on!
加密后的密文为：38fffa55167c75a24bc59c1dbb761f5cb8412aabe83ff5328a6394a909383d3856651af40e071fedb7c0af4b1e5ab2e9
经过解密后为：武汉，加油！中国，加油！！
