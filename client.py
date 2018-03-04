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

        pub_key = self.pks.get_encryption_key(self.username)
        sig_pub_key = self.pks.get_signature_key(self.username)

        # 1. Encrypt file first

        # Generate symm keys for MAC and file content
        symm_key_1 = self.crypto.get_random_bytes(32)
        symm_key_2 = self.crypto.get_random_bytes(32)

        symm_keys = symm_key_1 + "/" +symm_key_2;

        # Generate ciphers for those symmetric keys with asymmetric encryption
        c0 = self.crypto.asymmetric_encrypt(symm_keys, pub_key)

        # Encrypt file content with symm keys
        iv = self.crypto.get_random_bytes(16)
        c1 = self.crypto.symmetric_encrypt(value, symm_key_1, cipher_name='AES', mode_name='CBC', IV=iv, iv=None, counter=None, ctr=None, segment_size=None)
        # c2 = self.crypto.message_authentication_code(c1, symm_key_2, hash_name="SHA256")
        c2 = self.crypto.asymmetric_sign(c1, self.rsa_priv_key)

        file_contents = c0 + "/" + c1 + "/" + c2 + "/" + iv
        uid = self.crypto.get_random_bytes(32)

        # 2. Check for mapping of ‘username/dict/pw’: asymmencrypt(symm_key_for_dict, assymSign(symm_key_for_dict))
        id = self.username+"/dict/pw"
        enc_dictpw_stor_val = self.storage_server.get(id)

        # fileDict

        if not enc_dictpw_stor_val:
            #Create new dictionary
            dictpw = self.crypto.get_random_bytes(16)
            enc_dictpw = self.crypto.asymmetric_encrypt(dictpw, self.pks.get_encryption_key(self.username))
            iv2 = self.crypto.get_random_bytes(16)

            sig_enc_dictpw = self.crypto.asymmetric_sign(enc_dictpw, self.rsa_priv_key)

            enc_dictpw_stor_val = enc_dictpw + "/" + iv2 + "/" + sig_enc_dictpw
            self.storage_server.put(id, enc_dictpw_stor_val)

            fileDict = dict()

        else:
            stuff = enc_dictpw_stor_val.split("/")
            if len(stuff) != 3:
                return False
            enc_dictpw, iv2, sig_enc_dictpw = stuff
            if not self.crypto.asymmetric_verify(enc_dictpw, sig_enc_dictpw, self.pks.get_signature_key(self.username)):
                return False
            try:
                dictpw = self.crypto.asymmetric_decrypt(enc_dictpw, self.elg_priv_key)
            except:
                return False

            try:
                fileDict = self.get_dictionary(dictpw, iv2)
            except IntegrityError:
                return False

        hashed_name = self.crypto.cryptographic_hash(name, "SHA256")
        if hashed_name in fileDict:
            old_uid = fileDict[hashed_name]
            self.storage_server.delete(old_uid)

        fileDict[hashed_name] = uid

        self.storage_server.put(uid, file_contents)
        self.storage_server.put(self.username+"/dict", self.crypto.symmetric_encrypt(json.dumps(fileDict), dictpw, cipher_name='AES', mode_name='CBC', IV=iv2, iv=None, counter=None, ctr=None, segment_size=None))


    def download(self, name):
        # Replace with your implementation
        enc_dictpw =  self.storage_server.get(self.username+"/dict/pw")
        if not enc_dictpw:
            return None
        stuff = enc_dictpw.split("/")
        if len(stuff) != 3:
            raise IntegrityError
        enc_dict, iv, sig_enc_dictpw = enc_dictpw.split("/")
        if not self.crypto.asymmetric_verify(enc_dict, sig_enc_dictpw, self.pks.get_signature_key(self.username)):
            # print("sike")
            raise IntegrityError
        try:
            dictpw = self.crypto.asymmetric_decrypt(enc_dict, self.elg_priv_key)
        except:
            raise IntegrityError
        fileDict = self.get_dictionary(dictpw, iv)


        hashed_name = self.crypto.cryptographic_hash(name, hash_name="SHA256")
        if hashed_name not in fileDict:
            return None
        uid = fileDict[hashed_name]

        file_contents = self.storage_server.get(uid)

        fc_list = file_contents.split("/")

        if len(fc_list) != 4:
            raise IntegrityError

        c0 = fc_list[0]
        c1 = fc_list[1]
        c2 = fc_list[2]
        iv = fc_list[3]

        try:
            symm_keys = self.crypto.asymmetric_decrypt(c0, self.elg_priv_key).split("/")
            symm_key_1 = symm_keys[0]
            symm_key_2 = symm_keys[1]

            # if self.crypto.message_authentication_code(c1, symm_key_2, "SHA256") != c2:
            if not self.crypto.asymmetric_verify(c1, c2, self.pks.get_signature_key(self.username)):
                raise IntegrityError

            result = self.crypto.symmetric_decrypt(c1, symm_key_1, cipher_name='AES', mode_name='CBC', IV=iv, iv=None, counter=None, ctr=None, segment_size=None)
        except:
            raise IntegrityError

        return result



    def get_dictionary(self, enc_dictpw, iv):

        enc_fileDict = self.storage_server.get(self.username+"/dict")

        try:
            result = json.loads(self.crypto.symmetric_decrypt(enc_fileDict, enc_dictpw, 'AES', 'CBC', iv))
        except:
            raise IntegrityError

        return result

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError
