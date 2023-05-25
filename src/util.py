import json
import operator
import random
import secrets
import sympy
import zmq
import struct

# SOCKET
LOCAL_PORT = 4080
SERVER_HOST = "localhost"
SERVER_PORT = 4080


class Socket:
    def __init__(self, socket_type):
        self.socket = zmq.Context().socket(socket_type)

    def send(self, msg):
        self.socket.send_pyobj(msg)

    def receive(self):
        return self.socket.recv_pyobj()

    def send_wait(self, msg):
        self.send(msg)
        return self.receive()


class EvaluatorSocket(Socket):
    def __init__(self, endpoint=f"tcp://*:{LOCAL_PORT}"):
        super().__init__(zmq.REP)
        self.socket.bind(endpoint)


class GarblerSocket(Socket):
    def __init__(self, endpoint=f"tcp://{SERVER_HOST}:{SERVER_PORT}"):
        super().__init__(zmq.REQ)
        self.socket.connect(endpoint)


# PRIME GROUP
PRIME_BITS = 64  # order of magnitude of prime in base 2


def next_prime(num):
    """Return next prime after 'num' (skip 2)."""
    return 3 if num < 3 else sympy.nextprime(num)


def gen_prime(num_bits):
    """Return random prime of bit size 'num_bits'"""
    r = secrets.randbits(num_bits)
    return next_prime(r)


def xor_bytes(seq1, seq2):
    """XOR two byte sequence."""
    return bytes(map(operator.xor, seq1, seq2))


def bits(num, width):
    """Convert number into a list of bits."""
    return [int(k) for k in f'{num:0{width}b}']


class PrimeGroup:
    """Cyclic abelian group of prime order 'prime'."""
    def __init__(self, prime=None):
        self.prime = prime or gen_prime(num_bits=PRIME_BITS)
        self.prime_m1 = self.prime - 1
        self.prime_m2 = self.prime - 2
        self.generator = self.find_generator()

    def mul(self, num1, num2):
        "Multiply two elements." ""
        return (num1 * num2) % self.prime

    def pow(self, base, exponent):
        "Compute nth power of an element." ""
        return pow(base, exponent, self.prime)

    def gen_pow(self, exponent):  # generator exponentiation
        "Compute nth power of a generator." ""
        return pow(self.generator, exponent, self.prime)

    def inv(self, num):
        "Multiplicative inverse of an element." ""
        return pow(num, self.prime_m2, self.prime)

    def rand_int(self):  # random int in [1, prime-1]
        "Return an random int in [1, prime - 1]." ""
        return random.randint(1, self.prime_m1)

    def find_generator(self):  # find random generator for group
        """Find a random generator for the group."""
        factors = sympy.primefactors(self.prime_m1)

        while True:
            candidate = self.rand_int()
            for factor in factors:
                if 1 == self.pow(candidate, self.prime_m1 // factor):
                    break
            else:
                return candidate

    def __str__(self):
        return f"PrimeGroup(prime={self.prime}, generator={self.generator})"

def parse_json(json_path):
    with open(json_path) as json_file:
        return json.load(json_file)


def parse_float_set(s: str):
    if s[1:][:-1].strip() == "": # empty set
        return []
    str_list = s[1:][:-1].split(",")
    str_list = list(set(str_list)) # remove duplicates
    float_list = [float(x) for x in str_list]
    return float_list


def float_to_bit_list(x: float):
    """
    Convert a Python float into its "IEEE 754 binary32" 32 bit representation,
    returned as a list of 32 ints in {0, 1}.
    """
    bytes_ = struct.pack('>f', x) # get big-endian binary representation of x
    decoded_bytes = [b for b in bytes_] # turn bytes into integers
    binary_bytes = [bin(i)[2:] for i in decoded_bytes] # turn ints into binary strings of max 8 bits
    padded_bytes = [b.zfill(8) for b in binary_bytes]  # pad with leading 0s if needed
    bits = ''.join(padded_bytes)
    return [int(b) for b in bits]


class Logger:

    def __init__(self, party, mode, prepend="[-] "):
        self.party = party
        self.mode = mode
        self.pre = prepend
        if mode == "full":
            if party != "test":
                with open(f"output/ot_{party}.txt", "w") as f:
                    f.write("")
            if party == "Alice":
                with open("output/tables.txt", "w") as f:
                    f.write("")

    def minimal(self, s):
        if self.mode == "minimal":
            print(s)
        else:
            self.info("Result: " + s)

    def info(self, s):
        if self.mode in ["info", "full"]:
            print(self.pre + s)

    def ot(self, s):
        if self.mode == "full" and self.party != "test":
            with open(f"output/ot_{self.party}.txt", "a") as f:
                f.write(s + "\n")

    def circuit(self, s):
        if self.mode == "full":
            with open("output/tables.txt", "a") as f:
                f.write(s + "\n")