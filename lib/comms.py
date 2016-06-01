import struct

from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto import Random
from datetime import datetime
from lib.helpers import read_hex

from dh import create_dh_key, calculate_dh_secret

# Format used for timestamps used as our nonce
timestamp_format = "%Y-%m-%d %H:%M:%S:%f"
timestamp_format_len = 26

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.nonce = datetime.now()
        self.shared_hash = None
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(str(my_public_key))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            self.shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            if self.verbose:
                print("Shared hash: {}".format(self.shared_hash))
            self.shared_hash = bytes.fromhex(self.shared_hash)

        # AES is used in CFB mode with an IV that is initialised each time send() is called
        iv = self.shared_hash[:16] # set the initialization vector
        self.cipher = AES.new(self.shared_hash, AES.MODE_CFB, iv) # create cipher object

    def send(self, data):
        # Fix encoding for the data
        if type(data) != type(b""):
            data = bytes(data,'ascii')
    
        # Create a HMAC and prepend it to the message
        if self.shared_hash != None:
            h = HMAC.new(self.shared_hash)
            h.update(data)
            data_HMACed = bytes(h.hexdigest() + data.decode("ascii"),"ascii")
            # Use the following code if you want to test what happens when the HMAC is bad
            # data_HMACed = h.hexdigest()[:-1] + "a"  + data.decode("ascii") # replace a random character in the digest
        else:
            data_HMACed = data
        
        # Get current time
        time_now = datetime.now()
        # The following code can be used to test an invalid nonce
        # time_now = self.nonce - datetime.timedelta(2,0) # Take away 2 days from the last recieved message
        timestr = datetime.strftime(time_now, timestamp_format) # format the timestamp
        data_HMACed = bytes(timestr, 'ascii') + data_HMACed # prepend the HMAC to the message
            
        if self.cipher:
            encrypted_data = self.cipher.encrypt(data_HMACed) #Encrypt the HMACed message
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data_HMACed

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)


    def recv(self):
        # Decode the packet length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:
            data = self.cipher.decrypt(encrypted_data) # Decrypt the message
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        # strip off the HMAC and timestamp and verify the message
        # take off the timestamp first
        received_timestamp = str(data[:timestamp_format_len], 'ascii')
        data = data[timestamp_format_len:]
        
        # get the HMAC, if we're using one
        if self.shared_hash != None:
            h = HMAC.new(self.shared_hash)
            hmac = data[:h.digest_size * 2] # Get the HMAC from the received data
            data = data[h.digest_size * 2:] # Get the message from the received data
            h.update(data)
            if h.hexdigest() != str(hmac, 'ascii'): #HMAC is invalid, so raise an error
                if self.verbose:
                    print("Received HMAC:", str(hmac,'ascii'))
                    print("HMAC generated from digest:", h.hexdigest())
                    print("Unverified message:", data)
                raise RuntimeError("Bad message: HMAC does not match")
        elif self.verbose:
            print("Shared hash is None")
        
        # we'll only accept messages that have timestamps after the one we last recieved
        msg_time = datetime.strptime(received_timestamp, timestamp_format);
        if self.verbose:
            print(msg_time)
        if msg_time <= self.nonce: #If the timestamp is older, then raise an error
            if self.verbose:
                print("Invalid nonce")
                print("Timestamp:", received_timestamp)
            raise RuntimeError("Bad timestamp: message not newer than last recieved one")

        self.nonce = msg_time # Update nonce with latest received message time
                 
        return data

    def close(self):
        self.conn.close()
