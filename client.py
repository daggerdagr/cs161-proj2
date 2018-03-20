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

    def create_fileListPw(self):

        fileListPw_key = self.crypto.get_random_bytes(16)
        fileListPw_IV = self.crypto.get_random_bytes(16)

        # asym encrypt pw and push it up
        fileListPw_val = self.crypto.asymmetric_encrypt(fileListPw_key + "/" + fileListPw_IV,
                                                        self.pks.get_encryption_key(self.username))
        fileListPw_val_sign = self.crypto.asymmetric_sign(fileListPw_val, self.rsa_priv_key)
        self.storage_server.put(self.username + "/FileList/pw", fileListPw_val + "/" + fileListPw_val_sign)

        return fileListPw_key, fileListPw_IV


    def fileListGrabber(self):

        fileListPw_enc = self.storage_server.get(self.username + "/FileList/pw")
        fileList_val = self.storage_server.get(self.username + "/FileList")

        if fileList_val == None and fileListPw_enc == None:
            fileList = dict()
            fileListPw_key, fileListPw_IV = self.create_fileListPw()
            # TODO - why is this unused?

        else:

            # decrypt the password
            fileListPw_enc = fileListPw_enc.split("/")

            if len(fileListPw_enc) != 2:
                raise IntegrityError

            fileListPw_val, fileListPw_val_sign = fileListPw_enc

            # verify password
            try:
                if not self.crypto.asymmetric_verify(fileListPw_val, fileListPw_val_sign, self.pks.get_signature_key(self.username)):
                    raise IntegrityError
            except:
                raise IntegrityError

            # decrypting password and fileList
            try:
                fileListPw = self.crypto.asymmetric_decrypt(fileListPw_val, self.elg_priv_key)
            except:
                raise IntegrityError

            # getting symkey and IV
            fileListPw = fileListPw.split("/")
            if len(fileListPw) != 2:
                raise IntegrityError
            fileListPw_key, fileListPw_IV = fileListPw


            ## FILE LIST

            # decrypting fileList w symkey and IV

            fileList_val = fileList_val.split("/")
            if len(fileList_val) != 2:
                raise IntegrityError
            c0a, c0b = fileList_val

            # verifying if signature (c0b) for c0a is correcto
            try:
                if not self.crypto.asymmetric_verify(c0a, c0b, self.pks.get_signature_key(self.username)):
                    raise IntegrityError
            except:
                raise IntegrityError

            # decrypting c0a
            try:
                fileList = self.crypto.symmetric_decrypt(c0a, fileListPw_key, cipher_name='AES', mode_name='CBC', IV=fileListPw_IV, iv=None, counter=None, ctr=None, segment_size=None)
            except Exception as e:
                print(e.message)
                raise IntegrityError

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

            #### update fileList w new passwords
            # create password
            fileListPw_key, fileListPw_IV = self.create_fileListPw()

            # update fileList w new passwords
            fileList_enc = self.crypto.symmetric_encrypt(
                json.dumps(fileList), fileListPw_key, cipher_name='AES',
                mode_name='CBC', IV=fileListPw_IV, iv=None,
                counter=None,
                ctr=None, segment_size=None)
            fileList_enc_signed = self.crypto.asymmetric_sign(fileList_enc, self.rsa_priv_key)  # C9
            self.storage_server.put(self.username + "/FileList", "/".join([fileList_enc, fileList_enc_signed]))

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

            filePw_key, filePw_IV, filePw_mackey = self.create_filePw(self.username, fileUid)

        # 5.
        val = self.crypto.asymmetric_sign(fileUid, self.rsa_priv_key)
        fileContent_enc = self.crypto.symmetric_encrypt(value + "/" + val, filePw_key, cipher_name='AES',
                                mode_name='CBC', IV=filePw_IV, iv=None, counter=None, ctr=None,
                                                        segment_size=None)  # C4
        fileContent_enc_mac = self.crypto.message_authentication_code(fileContent_enc, filePw_mackey, "SHA256")

        self.storage_server.put(fileUid,"/".join([fileContent_enc, fileContent_enc_mac]))

        self.sofar = fileUid

        return True



    def download(self, name):

        if self.storage_server.get(self.username + "/FileList/pw") == None and self.storage_server.get(self.username + "/FileList") == None:
            return None

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
            if self.crypto.message_authentication_code(c4, filePw_mackey, "SHA256") != c5:
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
            self.crypto.asymmetric_verify(fileUid, val, self.pks.get_signature_key(self.username))
        except:
            raise IntegrityError

        return decFileContent


    def create_filePw(self, username, fileUid):
        filePw_key = self.crypto.get_random_bytes(32)
        filePw_IV = self.crypto.get_random_bytes(16)
        filePw_mackey = self.crypto.get_random_bytes(32)

        self.store_filePw(username, fileUid, filePw_key, filePw_IV, filePw_mackey)

        return [filePw_key, filePw_IV, filePw_mackey]

    def store_filePw(self, username, fileUid, filePw_key, filePw_IV, filePw_mackey):
        orig = "/".join([filePw_key, filePw_IV, filePw_mackey, fileUid])

        try:
            store_val_enc = self.crypto.asymmetric_encrypt(orig, self.pks.get_encryption_key(username))  # C8
        except:
            return False

        # print("1:" + store_val_enc)
        self.storage_server.put("/".join([username, fileUid, "pw"]), store_val_enc)


    def get_passwords(self, fileUid):
        ## GET PASSWORDS

        # GET enc(password) + signed version of that
        filePw_val = self.storage_server.get("/".join([self.username, fileUid, "pw"]))
        # print("2:" + filePw_val)

        try:
            filePw_dec = self.crypto.asymmetric_decrypt(filePw_val, self.elg_priv_key)
        except:
            return None

        # verify if encrypted password is signed

        filePw_dec = filePw_dec.split("/")
        if len(filePw_dec) != 4:
            return None

        filePw_key = filePw_dec[0]
        filePw_IV = filePw_dec[1]
        filePw_mackey = filePw_dec[2]
        intended_fileUid = filePw_dec[3]

        if intended_fileUid != fileUid:
            return None

        return filePw_key, filePw_IV, filePw_mackey




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
        # raise NotImplementedError

        fileList = self.fileListGrabber()
        fileNameHash = self.crypto.cryptographic_hash(name, hash_name="SHA256")

        if fileNameHash in fileList:
            fileUid = fileList[fileNameHash]
        else:
            raise IntegrityError # TODO - review if this should be returned

        #### get privateList

        privateList = None # TODO - temporary

        if user not in privateList:
            return False # TODO - making it s.t. it returns True if successful, False if it doens't

        privateList.remove(name)

        # generate new passwords
        filePw_key, filePw_IV, filePw_mackey = self.create_filePw(self, self.username, fileUid)

        ### get publicList

        publicList = None # TODO - temporary

        newPublicList = dict()

        for direct_name in privateList:
            val = publicList[direct_name]

            self.publicListUpdate(direct_name, publicList, newPublicList)


        # update everyone who's made it here

        updated_so_far = set()

        for direct_name, indirect_list in newPublicList.values():
            if direct_name not in updated_so_far:
                self.store_filePw(direct_name, fileUid, filePw_key, filePw_IV, filePw_mackey)
                updated_so_far.add(direct_name)
            for indirect_name in indirect_list:
                if indirect_name not in updated_so_far:
                    self.store_filePw(indirect_name, fileUid, filePw_key, filePw_IV, filePw_mackey)
                    updated_so_far.add(indirect_name)

        # update values

        for direct_name, indirect_list in newPublicList.values():
            # indirect_list = encrypt indirect_list
            newPublicList[direct_name] = indirect_list

def publicListUpdate(self, username, oldDict, newDict):
    entry = oldDict[username]

    # verify and decrypt

    # update

    newDict[username] = name_list

    for name in name_list:
        if name not in newDict:
            publicListUpdate(self, name, oldDict, newDict)










