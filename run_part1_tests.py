#!/usr/bin/env python3

"""Autograder tests for Part 1.

Run this script (``python3 run_part1_tests.py``) from the same directory as
your ``client.py`` file. This will run all of the functionality tests for
Part 1 of the project.
"""

import random
import traceback
import inspect
from servers import StorageServer, PublicKeyServer
from base_client import IntegrityError
from crypto import Crypto
from random import shuffle

#########################
#  FUNCTIONALITY TESTS  #
#########################

globs = dict(globals())


def t01_SimpleGetPut(C, pks, crypto, server):
    """Uploads a single file and checks the downloaded version is correct."""
    alice = C("alice")
    alice.upload("a", "b")
    return float(alice.download("a") == "b")


def t02_SimpleGetPutNoState(C, pks, crypto, server):
    """Verifies that clients maintain no state about keys stored."""
    score = 0

    alice = C("alice")
    alice2 = C("alice")
    alice.upload("a", "b")
    score += alice2.download("a") == "b"

    server.kv = {}
    alice = C("alice")
    alice2 = C("alice")
    alice2.upload("a", "b")
    score += alice.download("a") == "b"

    server.kv = {}
    alice = C("alice")
    alice.upload("a", "b")
    alice2 = C("alice")
    score += alice2.download("a") == "b"

    return float(score) / 3.0


def t03_SingleClientManyPuts(C, pks, crypto, server):
    return 1.0
    """Uploads many files for the same user and checks they all uplad
    correctly."""
    alice = C("alice")
    kv = {}
    for r in range(100):
        uuid1 = "%08x" % random.randint(0, 100)
        uuid2 = "%08x" % random.randint(0, 100000)
        kv[uuid1] = uuid2
        alice.upload(uuid1, uuid2)

    for k, v in kv.items():
        if alice.download(k) != v:
            return 0.0
    return 1.0


def t04_ValueDNE(C, pks, crypto, server):
    """Checks that values not stored at the server return None."""
    score = 0
    alice = C("alice")
    score += alice.download("a") is None
    score += alice.download("b") is None
    score += alice.download("c") is None
    alice.upload("d", "e")
    score += alice.download("e") is None
    score += alice.download("d") == "e"
    return float(score) / 5.0


def t05_NonCollidingNames(C, pks, crypto, server):
    """Uploads a file with the same name from two different users and checks for
    collisions."""
    alice = C("alice")
    bob = C("bob")
    alice.upload("a", "b")
    bob.upload("a", "c")
    return ((alice.download("a") == "b") + (bob.download("a") == "c")) / 2.0


def t06_ManyGetPuts(C, pks, crypto, server):
    return 1.0
    """Many clients upload many files and their contents are checked."""
    clients = [C("c" + str(n)) for n in range(10)]

    kvs = [{} for _ in range(10)]

    for _ in range(200):
        i = random.randint(0, 9)

        uuid1 = "%08x" % random.randint(0, 100)
        uuid2 = "%08x" % random.randint(0, 100)
        clients[i].upload(str(uuid1), str(uuid2))
        kvs[i][str(uuid1)] = str(uuid2)

    good = total = 0
    # verify integrity
    for i, (c, kv) in enumerate(zip(clients, kvs)):
        for k, v in kv.items():
            vv = c.download(k)
            if vv == v:
                good += 1
            total += 1
    return float(good) / total


def t07_SimpleGetPut(C, pks, crypto, server):
    """Tests that the server can handle long file names and keys"""
    alice = C("alice")
    alice.upload("a" * 1000, "b" * 1000)
    return float(alice.download("a" * 1000) == "b" * 1000)

def tc0(C, pks, crypto, server):
    alice = C("alice")
    bob = C("bob")
    a_name = crypto.get_random_bytes(32)
    a_val = crypto.get_random_bytes(32)
    alice.upload(a_name, a_val)
    aliceFileUID = alice.sofar

    b_name = crypto.get_random_bytes(32)
    b_val = crypto.get_random_bytes(32)
    bob.upload(b_name, b_val)
    bobFileUID = bob.sofar

    serverFileContentBob = server.kv[bobFileUID]
    server.kv[bobFileUID] = server.kv[aliceFileUID]
    server.kv[aliceFileUID] = serverFileContentBob

    bool1 = False
    try:
        alice.download(a_name)
    except IntegrityError:
        bool1 = True

    bool2 = False
    try:
        bob.download(b_name)
    except IntegrityError:
        bool2 = True

    return bool1 and bool2


def tc1(C, pks, crypto, server):
    alice = C("alice")
    bob = C("bob")
    a_name = crypto.get_random_bytes(32)
    a_val = crypto.get_random_bytes(32)
    alice.upload(a_name, a_val)
    aliceFileUID = alice.sofar

    b_name = crypto.get_random_bytes(32)
    b_val = crypto.get_random_bytes(32)
    bob.upload(b_name, b_val)
    bobFileUID = bob.sofar

    bool1 = False
    try:
        bool1 = None == alice.download(b_name)
    except IntegrityError:
        bool1 = True

    bool2 = False
    try:
        bool2 = None == bob.download(a_name)
    except IntegrityError:
        bool2 = True

    serverFileContentBob = server.kv[bobFileUID]
    server.kv[bobFileUID] = server.kv[aliceFileUID]
    server.kv[aliceFileUID] = serverFileContentBob

    bool3 = False
    try:
        bool3 = None == alice.download(b_name)
    except IntegrityError:
        bool3 = True

    bool4 = False
    try:
        bool4 = None == bob.download(a_name)
    except IntegrityError:
        bool4 = True

    return bool1 and bool2 and bool3 and bool4

# def tc2(C, pks, crypto, server):
#     alice = C("alice")
#     a_name = crypto.get_random_bytes(32)
#     a_val = crypto.get_random_bytes(32)
#     alice.upload(a_name, a_val)
#     aliceFileUID = alice.sofar
#
#     del server.kv[aliceFileUID]

def tc3(C, pks, crypto, server):
    alice = C("alice")
    bob = C("bob")
    a1_name = crypto.get_random_bytes(32)
    a1_val = crypto.get_random_bytes(32)
    alice.upload(a1_name, a1_val)
    aliceFileUID1 = alice.sofar

    a2_name = crypto.get_random_bytes(32)
    a2_val = crypto.get_random_bytes(32)
    alice.upload(a2_name, a2_val)
    aliceFileUID2 = alice.sofar

    serverFileContentAlice = server.kv[aliceFileUID1]
    server.kv[aliceFileUID1] = server.kv[aliceFileUID2]
    server.kv[aliceFileUID2] = serverFileContentAlice

    try:
        alice.download(a1_name)
    except IntegrityError:
        return True


    return False

def tc4(C, pks, crypto, server):
    """Uploads a single file and checks the downloaded version is correct."""
    alice = C("alice")
    alice.upload("a", "b")
    alice.upload("a", "c")
    return float(alice.download("a") == "c")


class MastermindServer(StorageServer):

    def scramble(self):
        keys = list(self.kv.keys())
        vals = list(self.kv.values())

        shuffle(keys)
        shuffle(vals)
        for key, val in keys, vals:
            self.put(key, val)




gs = dict(globals())

functionality_tests = []
for g, f in sorted(gs.items()):
    if (g not in globs and g != "globs" and "__" not in g and
            type(f) == type(lambda x: x)):
        functionality_tests.append((g, f))


class ByteChangingServer(StorageServer):
    """Sample malicious server that randomly changes bytes."""
    def get(self, k):
        if k not in self.kv:
            return None
        v = self.kv[k]
        if random.randint(0, 5) != 0:
            return v
        flip = random.randint(0, len(v)-1)
        return v[:flip] + chr(random.randint(0, 255)) + v[flip+1:]

def VillainTester(C, pks, crypto, server=MastermindServer):
    """Runs all functionality tests with a fuzz testing server."""
    print("Running all part 1 functionality tests with villain testing server...")
    for name, test in functionality_tests:
        print("\t"+name)
        try:
            score = 0
            for _ in range(30):
                server.kv = {}
                score += test(C, pks, crypto, server)
            score /= 30
            print("\tscore: "+str(score))
            if score < .999:
                print("\tTest", name, "failed against the villain testing server.")
        except IntegrityError:
            print("\tscore: 1")
            pass
        except:
            print("\tAn exception was generated while running the villain server.")
            traceback.print_exc()

def FuzzTester(C, pks, crypto, server=ByteChangingServer):
    """Runs all functionality tests with a fuzz testing server."""
    print("Running all part 1 functionality tests with fuzz testing server...")
    for name, test in functionality_tests:
        print("\t"+name)
        try:
            score = 0
            for _ in range(30):
                server.kv = {}
                score += test(C, pks, crypto, server)
            score /= 30
            print("\tscore: "+str(score))
            if score < .999:
                print("\tTest", name, "failed against the fuzz testing server.")
        except IntegrityError:
            print("\tscore: 1")
            pass
        except:
            print("\tAn exception was generated while running the fuzz server.")
            traceback.print_exc()


class StudentTester:
    def __init__(self, theclass):
        self.theclass = theclass

    def run_test(self, t, Server=StorageServer, Crypto=Crypto,
                 Pks=PublicKeyServer):
        argspec = inspect.getargspec(t)
        if argspec.defaults is None:
            types = {}
        else:
            types = dict(zip(argspec.args[-len(argspec.defaults):],
                             argspec.defaults))

        server = types['server']() if 'server' in types else Server()
        pks = types['pks']() if 'pks' in types else Pks()
        crypto = types['crypto']() if 'crypto' in types else Crypto()
        myclient = __import__(self.theclass, fromlist=[''])

        def C(name):
            return myclient.Client(server, pks, crypto, name)
        return t(C, pks, crypto, server)


def run_part1_tests():
    """Runs all part 1 functionality tests."""
    for testname, test in functionality_tests:
        print("============")
        print("Running test", testname)
        try:
            score = StudentTester("client").run_test(test)
            if score >= .99999:
                print("\tTest Passes.")
            else:
                print("\tTest FAILED.")
                print("\t"+test.__doc__)
        except:
            print("\tTest FAILED.")
            print("\t"+test.__doc__)
            traceback.print_exc()
            print("\n\n")
    StudentTester("client").run_test(FuzzTester)


if __name__ == "__main__":
    print("PART 1 TESTS")
    run_part1_tests()
