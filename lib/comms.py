import struct

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

from dh import create_dh_key, calculate_dh_secret

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]
shared_hash = ""

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            global shared_hash
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))

        # Default XOR algorithm can only take a key of length 32
        # change this to a block cipher
        # generate IV based on shared hash, reinitialise cipher each time send() is called
        self.iv = Random.new().read(AES.block_size)
        self.cipher = AES.new(shared_hash[:32], AES.MODE_CBC, self.iv)
        # adding HMAC for each message using SHA256
        hmac - HMAC.new(self.cipher, digestmod = SHA256)

    def send(self, data):
        # send IV + encrypted message (encrypt the message + HMAC)
        if self.cipher:
            data = pad(str(data))
            self.iv = Random.new().read(AES.block_size)
            self.cipher = AES.new(shared_hash[:32], AES.MODE_CBC, self.iv)
            encrypted_data = self.iv + self.cipher.encrypt(data)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        # use IV to reinitialise the cipher so that we can decrypt the message
        # decrypted message contains HMAC at the end
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:
            iv = encrypted_data[:16]
            self.cipher = AES.new(shared_hash[:32], AES.MODE_CBC, iv)
            data = self.cipher.decrypt(encrypted_data[16:]).decode("utf-8")
            data = unpad(data)

            print("Receiving packet of length {}".format(pkt_len))
            print("Encrypted data: {}".format(repr(encrypted_data)))
            print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()
