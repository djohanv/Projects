def prime_checker(num):
    """
    To check if the number is prime or not
    :return:
    """
    checker = True
    counter = 0
    if num > 1:
        if num % 2 != 0:
            for i in range(3, num + 1):
                if num % i == 0:
                    counter += 1
                    if num == i and counter == 1:
                        checker = True
                else:
                    checker = False
        else:
            checker = False
    return checker


e = 17
z = 47040

def create_d(e, z):
    """
    To generate the private key d from (de%z == 1)
    :return: d
    """
    d = 0
    new_d = 1
    r = z
    new_r = e
    var = 0
    while new_r != 0:
        var = r // new_r
        (d, new_d) = (new_d, d-var * new_d)
        (r, new_r) = (new_r, r - var * new_r)
    if r > 1:
        return "Not invertible"
    elif d < 0:
        d = d + z
    print(d)
    return d

my_tup = (17, 48319)


def find_p_and_q(n):
    """
    To find the factors of n which is p and q
    :param n: the public modulus
    :return:
    """
    temp_list = []
    while n > 1:
        for i in range(2, n + 1):
            if n % i == 0:
                n /= i
                temp_list.append(i)
    tup_p_q = (temp_list[0], temp_list[1])
    return tup_p_q

print(find_p_and_q(my_tup[1]))

