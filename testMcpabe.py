'''
:Authors:         hiwei
:Date:            7/2020
'''

import sys
sys.path.append("..")
from charm.toolbox.pairinggroup import PairingGroup, GT
from waters2015 import MCPABE
import time

def main():
    # instantiate a bilinear pairing map

    pairing_group = PairingGroup('SS512')


    cpabe = MCPABE(pairing_group, 10, 8, 250)
    H = cpabe.H()
    U = cpabe.U()
    Ua = cpabe.Ua()
    F1,F2 = cpabe.F()
    T = cpabe.T()

    # run the set up
    PP = cpabe.setup(H, F1, F2, U, Ua ,T)
    AA1_PK, AA1_SK = cpabe.AuthoritySetup(1, PP)
    AA2_PK, AA2_SK = cpabe.AuthoritySetup(2, PP)
    AA3_PK, AA3_SK = cpabe.AuthoritySetup(3, PP)
    AA4_PK, AA4_SK = cpabe.AuthoritySetup(4, PP)
    AA5_PK, AA5_SK = cpabe.AuthoritySetup(5, PP)
    AA6_PK, AA6_SK = cpabe.AuthoritySetup(6, PP)
    AA7_PK, AA7_SK = cpabe.AuthoritySetup(7, PP)
    AA8_PK, AA8_SK = cpabe.AuthoritySetup(8, PP)
    SKaid = {}
    SKaid.update(AA1_SK)
    SKaid.update(AA2_SK)
    SKaid.update(AA3_SK)
    SKaid.update(AA4_SK)
    SKaid.update(AA5_SK)
    SKaid.update(AA6_SK)
    SKaid.update(AA7_SK)
    SKaid.update(AA8_SK)
    #print(SKaid)


    # generate user1's key
    attr_list = ['A1', 'A2', 'A3', 'A4', 'A5', 'A6', 'A7', 'A8', 'A9', 'A10']
    PKaid = {}
    for attr in attr_list:
        aid = PP['T'][attr]
        if aid == 1:
            PKaid.update(AA1_PK)
        if aid == 2:
            PKaid.update(AA2_PK)
        if aid == 3:
            PKaid.update(AA3_PK)
        if aid == 4:
            PKaid.update(AA4_PK)
        if aid == 5:
            PKaid.update(AA5_PK)
        if aid == 6:
            PKaid.update(AA6_PK)
        if aid == 7:
            PKaid.update(AA7_PK)
        if aid == 8:
            PKaid.update(AA8_PK)
    #print(PKaid)

    gid = 1
    key = cpabe.keygen(gid, attr_list, SKaid, PP)
    #print(key)


    # choose a random message
    msg = pairing_group.random(GT)

    # generate a ciphertext
    policy_str = '(A1 and A2 and A3 and A4 and A5 and A6 and A7 and A8 )'
    ctxt = cpabe.encrypt(PKaid, msg, policy_str, PP)
    #print(ctxt)

    # decryption
    rec_msg = cpabe.decrypt(gid, ctxt, key, PP)
    print(msg)
    print(rec_msg)
    if debug:
        if rec_msg == msg:
            print("Successful decryption.")
        else:
            print("Decryption failed.")


if __name__ == "__main__":
    debug = True
    start = time.clock()
    main()
    end = time.clock()
    print("final is in ", end - start)