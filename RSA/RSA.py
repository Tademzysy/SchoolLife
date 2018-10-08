import random
from function import *

num_len = 512  #素数比特长


F_array=[]

while True:
	x = random.randrange(pow(2, num_len-1), pow(2, num_len))
	if Fermat_primality_test(x) == 1:
		F_array.append(x)
	if len(F_array) == 2:
		break  #产生指定范围内的两个随机素数

print("p: ", F_array[0])
print("q: ", F_array[1])  #产生两个素数


N = F_array[0] * F_array[1] #素数乘积
L = LCM(F_array[0]-1, F_array[1]-1) #中间量 用于产生E、D
print('N:',N)
print('L:',L)


for x in range(2, L):
	if GCD(x, L) == 1:
		E = x
		break

print('this is E:',E)


D = modular_inversion(E, L)
print('this is D:', D)



public_key = E, N
private_key = D, N

print('public_key:',public_key)
print('private_key:',private_key)

plain_text = input(" enter the plaintext: ")


print("plain_text: {}".format(plain_text))
bits_flow = transform_bitsflow(plain_text)

#分组加密
result = ''
for i in range(0, len(bits_flow) // 8):
	son_bitsflow = bits_flow[(i*8) : (i+1)*8]
	int_plaintext = int(son_bitsflow, 2)
	cipher_number = pow(int_plaintext, E, N)
	result += str(cipher_number) + ','

print("cipher_number:{}".format(result.replace(',',''))) #输出密文

#解密
x = result.split(',')
x.pop(-1)


rr = ''
for i in range(0,len(x)):
	son_plaintext = pow(int(x[i]), D, N)
	true_son_plaintext = str(bin(son_plaintext)).replace('b','')
	if len(true_son_plaintext) < 8:
		true_son_plaintext = '0' * (8 - len(true_son_plaintext)) + true_son_plaintext
	result_palintext = chr(int(true_son_plaintext, 2))
	rr += result_palintext


print("plaintext after decoding:{}".format(rr))


