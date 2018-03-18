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


    def fileListGrabber(self):

        fileListPw_enc = self.storage_server.get(self.username + "/FileList/pw")
        fileList_val = self.storage_server.get(self.username + "/FileList")

        if fileList_val == None and fileListPw_enc == None:
            fileList = dict()
            fileListPw_key = self.crypto.get_random_bytes(16)
            fileListPw_IV = self.crypto.get_random_bytes(16)

            # asym encrypt pw and push it up
            fileListPw_val = self.crypto.asymmetric_encrypt(fileListPw_key + "/" + fileListPw_IV, self.pks.get_encryption_key(self.username))
            fileListPw_val_sign = self.crypto.asymmetric_sign(fileListPw_val, self.rsa_priv_key)
            self.storage_server.put(self.username + "/FileList/pw", fileListPw_val + "/" + fileListPw_val_sign)

        else:

            # decrypt the password
            fileListPw_enc = fileListPw_enc.split("/")

            if len(fileListPw_enc) != 2:
                return None

            fileListPw_val, fileListPw_val_sign = fileListPw_enc

            # verify password
            try:
                if not self.crypto.asymmetric_verify(fileListPw_val, fileListPw_val_sign, self.pks.get_signature_keys(self.username)):
                    return None
            except:
                return None

            # decrypting password and fileList
            try:
                fileListPw = self.crypto.asymmetric_decrypt(fileListPw_val, self.elg_priv_key)
            except:
                return None

            # getting symkey and IV
            fileListPw = fileListPw.split("/")
            if len(fileListPw) != 2:
                return None
            fileListPw_key, fileListPw_IV = fileListPw


            ## FILE LIST

            # decrypting fileList w symkey and IV

            fileList_val = fileList_val.split("/")
            if len(fileList_val) != 2:
                return None
            c0a, c0b = fileList_val

            # verifying if signature (c0b) for c0a is correcto
            try:
                if not self.crypto.asymmetric_verify(c0a, c0b, self.pks.get_signature_key(self.username)):
                    return None
            except:
                return None

            # decrypting c0a
            try:
                fileList = self.crypto.symmetric_decrypt(c0a, fileListPw, cipher_name='AES', mode_name='CBC', IV=fileListPw_IV, iv=None, counter=None, ctr=None, segment_size=None)
            except:
                return None

            # converting string format fileList to actual dictionary
            fileList = json.loads(fileList)


        return fileList



    def upload(self, name, value):
        # Replace with your implementation

        fileList = self.fileListGrabber()

        if fileList == None:
            return False

        fileNameHash = self.crypto.cryptographic_hash(name, hash_name="SHA256")


        if fileNameHash in fileList:
            fileUid = fileList[fileNameHash]

            ## GET PASSWORDS

            filePw_dec = self.get_passwords(fileUid)

            if filePw_dec == None:
                return False

            filePw_key, filePw_IV, filePw_mackey = filePw_dec

        else:

            ## CREATE PRIVATE LIST

            fileUid = self.crypto.get_random_bytes(32) + "_by" + self.username

            fileList[fileNameHash] = fileUid

            shared_list = set()

            counter = self.crypto.get_random_bytes(16)

            content = fileUid + repr(shared_list) + counter

            try:
                content_enc = self.crypto.asymmetric_encrypt(content, self.pks.get_encryption_key(self.username)) # C8
                content_enc_sign = self.crypto.asymmetric_sign(content_enc, self.rsa_priv_key) # C9
            except:
                return False

            store_val = content_enc + "/" + content_enc_sign

            self.storage_server.put(self.username + "/" + fileUid + "/private", store_val)

            ## CREATE PASSWORDS

            filePw_key = self.crypto.get_random_bytes(32)
            filePw_IV = self.crypto.get_random_bytes(16)
            filePw_mackey = self.crypto.get_random_bytes(32)

            orig = "/".join([filePw_key, filePw_IV, filePw_mackey, fileUid])

            try:
                orig_sign = self.crypto.asymmetric_sign(orig, self.rsa_priv_key)
            except:
                return False

            store_val = "/".join([orig, orig_sign])

            try:
                store_val_enc = self.crypto.asymmetric_encrypt(store_val, self.pks.get_encryption_key(self.username)) # C8
            except:
                return False

            self.storage_server.put("/".join([self.username, fileUid, "pw"]), store_val_enc)

        # 5.
        fileContent_enc = self.crypto.symmetric_encrypt(value, filePw_key, cipher_name='AES', mode_name='CBC', IV=filePw_IV, iv=None, counter=None, ctr=None, segment_size=None) # C4
        val = self.crypto.asymmetric_sign(fileUid, self.rsa_priv_key)
        fileContent_enc_mac = self.crypto.message_authentication_code(fileContent_enc, filePw_mackey, "SHA256")

        self.storage_server.put(fileUid,"/".join([fileContent_enc + "/" + val, fileContent_enc_mac]))

        return True



    def download(self, name):

        # 1. & 2. Grabbing file list
        fileList = self.fileListGrabber()

        if fileList == None:
            return None

        fileNameHash = self.crypto.cryptographic_hash(name, hash_name="SHA256")

        # 3. Checking file list for filenamehash
        if fileNameHash not in fileList:
            return None

        # 4. Grabbing symm key and MAC for object
        fileUid = fileList[fileNameHash]

        filePw_dec = self.get_passwords(fileUid)

        if filePw_dec == None:
            raise IntegrityError

        filePw_key, filePw_IV, filePw_mackey = filePw_dec

        # 5. Retrieve value mapped to "File1ObjUid_byOwner"
        fileContent = self.storage_server.get(fileUid)
        fileContent = fileContent.split("/")
        if len(fileContent) != 2:
            raise IntegrityError

        c4, c5 = fileContent  # c4, c5

        try:
            if self.crypto.message_authentication_code(c4, filePw_mackey) != c5:
                raise IntegrityError
        except:
            raise IntegrityError

        try:
            fileContentandSign = self.crypto.symmetric_decrypt(c4, filePw_key, 'AES', 'CBC', filePw_IV)
        except:
            raise IntegrityError

        fileContentandSign = fileContentandSign.split("/")
        if len(fileContentandSign) != 2:
            raise IntegrityError

        decFileContent, val = fileContentandSign

        try:
            self.crypto.asymmetric_verify(fileUid, val, self.pks.get_signature_keys(self.username))
        except:
            raise IntegrityError

        return decFileContent




    def get_passwords(self, fileUid):
        ## GET PASSWORDS

        # GET enc(password) + signed version of that
        filePw_val = self.storage_server.get("/".join([self.username, fileUid, "pw"]))

        # verify if encrypted password is signed
        filePw_val = filePw_val.split("/")  # val
        if len(filePw_val) != 2:
            return None
        filePw_enc, filePw_enc_signed = filePw_val  # c1, c2

        if not self.crypto.asymmetric_verify(filePw_enc, filePw_enc_signed,
                                             self.pks.get_signature_keys(self.username)):
            return None

        try:
            filePw_dec = self.crypto.asymmetric_decrypt(filePw_val, self.elg_priv_key)
        except:
            return None

        filePw_dec = filePw_dec.split("/")
        if len(filePw_dec) != 3:
            return None

        return filePw_dec




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
