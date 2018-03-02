"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError
import json


class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)

    def upload(self, name, value):
        # Replace with your implementation

        pub_key = public_key_server.get_encryption_key()
        sig_pub_key = public_key_server.get_signature_key()

        # 1. Encrypt file first

        # Generate symm keys for MAC and file content
        symm_key_1 = get_random_bytes(32)
        symm_key_2 = get_random_bytes(32)

        # Generate ciphers for those symmetric keys with asymmetric encryption
        c0a = asymmetric_encrypt(symm_key_1, pub_key)
        c0b = asymmetric_encrypt(symm_key_2, pub_key)

        # Encrypt file content with symm keys
        iv = get_random_bytes(32)
        c1 = symmetric_encrypt(value, symm_key_1, cipher_name='AES', mode_name='CBC', IV=iv, iv=None, counter=None, ctr=None, segment_size=None, **kwargs=None)
        c2 = message_authentication_code(c1, symm_key_2, hash_name=None)

        file_contents = c0a + "/" + c0b + "/" + c1 + "/" + c2 + "/" + iv
        uid = get_random_bytes(32)

        # 2. Check for mapping of ‘username/dict/pw’: asymmencrypt(symm_key_for_dict, assymSign(symm_key_for_dict))
        id = self.username+"/dict/pw"
        enc_dictpw = self.storage_server.get(id)

        # fileDict

        if not enc_dictpw:
            #Create new dictionary
            dictpw = get_random_bytes(32)
            p = dictpw + "/" + asymmetric_sign(dictpw, self.rsa_priv_key)
            enc_p = asymmetric_encrypt(p, public_key_server.get_encryption_key(self.username)) 
            self.storage_server.put(id, enc_p)

            fileDict = dict()

        else:
            fileDict = get_dictionary(enc_dictpw)
       
        hashed_name = cryptographic_hash(name)
        if hashed_name in fileDict:
            old_uid = fileDict[hashed_name]
            self.storage_server.delete(old_uid)
        
        fileDict[hashed_name] = uid

        self.storage_server.put(uid, file_contents)
        self.storage_server.put(self.username+"/dict", symmetric_encrypt(json.dumps(fileDict), dictpw))
            

    def download(self, name):
        # Replace with your implementation
        enc_dictpw =  self.storage_server.get(self.username+"/dict/pw")
        if not enc_dictpw: 
            return None
        fileDict = get_dictionary(enc_dictpw)

        hashed_name = cryptographic_hash(name)
        if hashed_name not in fileDict:
            return None
        uid = fileDict[hashed_name]
        
        file_contents = self.storage_server.get(uid)

        fc_list = file_contents.split("/")

        c0a = fc_list[0]
        c0b = fc_list[1]
        c1 = fc_list[2]
        c2 = fc_list[3]
        iv = fc_list[4]

        symm_key_1 = asymmetric_decrypt(c0a, self.elg_priv_key)
        symm_key_2 = asymmetric_decrypt(c0b, self.elg_priv_key)
        if message_authentication_code(symm_key_2, c1) != c2:
            raise IntegrityError
        
        return symmetric_decrypt(c1, symm_key_1, cipher_name='AES', mode_name='CBC', IV=iv, iv=None, counter=None, ctr=None, segment_size=None, **kwargs=None)


    
    def get_dictionary(self, enc_dictpw):
        dec_dictpw = asymmetric_decrypt(enc_dictpw, self.elg_priv_key)
        dictpw, sign_dictpw = dec_dictpw.split("/")
        if not asymmetric_verify(dictpw, sign_dictpw, public_key_server.get_signature_key(self.username)):
            raise IntegrityError
        
        enc_fileDict = self.storage_server.get(self.username+"/dict")

        return json.loads(symmetric_decrypt(enc_fileDict, dictpw))

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError
