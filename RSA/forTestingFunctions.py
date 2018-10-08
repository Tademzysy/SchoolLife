def GCD(num1, num2):
	while(num2 != 0):
		r = num1 % num2
		num1 = num2
		num2 = r
	return num1
#最大公因数
def LCM(num1, num2):
	return num1 * num2 //GCD(num1, num2)
#最小公倍数
def Fermat_primality_test(w_prime_num, top = 100):
	a_Array = []

	for a in range(1, top):
		if GCD(a, w_prime_num):
			a_Array.append(a)


	for i in range(0, len(a_Array)):
		if(pow(a_Array[i], w_prime_num-1, w_prime_num) != 1):
			return 0  #合数
		else:
			continue


	return 1 #素数


def transform_bitsflow(string):
	bits_flow = ''
	for char in string:
		son_bitsflow = str(bin(ord(char))).replace('0b','')
		if len(son_bitsflow) < 8:
			son_bitsflow = '0' * (8 - len(son_bitsflow)) + son_bitsflow
		bits_flow += son_bitsflow

	return bits_flow


def modular_inversion(a,b):
	if GCD(a,b)!=1:
		return None

	u1,u2,u3=1,0,a
	v1,v2,v3=0,1,b

	while v3!=0:
		q=u3//v3
		v1,v2,v3,u1,u2,u3=(u1-q*v1),(u2-q*v2),(u3-q*v3),v1,v2,v3

	return u1%b


if __name__ == '__main__':
    print(modular_inversion(7, 4870))
