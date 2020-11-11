#-*- coding: utf-8 -*-

'''

| Security Assumption: Decisional q-Parallel Bilinear Diffie-Hellman Exponent
|
| type:           ciphertext-policy attribute-based encryption
| setting:        Pairing

:Authors:         hiwei
:Date:            7/2020
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP
import random
import hashlib

debug = False


class MCPABE(ABEnc):

    def __init__(self, group_obj, id_size, AA_size, uni_size, verbose=False):
        ABEnc.__init__(self)
        self.group = group_obj
        self.id_size = id_size #
        self.AA_size = AA_size #
        self.uni_size = uni_size  # bound on the size of the universe of attributes
        self.util = MSP(self.group, verbose)

    def H(self):
        h1 = {} #H1是将用户身份(gid)映射到G中元素
        for i in range(self.id_size):
            h1[i+1] = self.group.random(G1)
        return h1

    def U(self):
        u = {}  # H1是将用户身份(gid)映射到G中元素
        for i in range(self.uni_size):
            u['A'+str(i+1)] = 'A'+str(i+1)
        return u

    def Ua(self):
        ua = {}  # H1是将用户身份(gid)映射到G中元素
        for i in range(self.AA_size):
            ua[i+1] = i+1
        return ua

    def F(self):
        f1 = {}
        f2 = {}#H2是将用户的属性映射到G中元素
        for i in range(self.uni_size):
            f1['A'+str(i+1)] = self.group.random(G1)
            f2['A'+str(i+1)] = self.group.random(G2)
        return f1,f2

    def T(self):
        t = {}      #T是将输入属性i映射到相应的授权机构aid
        for i in range(self.uni_size):
            t['A'+str(i+1)] = random.randint(1, self.AA_size)
        return t

    def setup(self, H, F1, F2, U, Ua ,T):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('Setup algorithm:\n')

        # pick a random element each from two source groups and pair them
        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        e_gg = pair(g1, g2)


        GP = {'g1': g1, 'g2': g2, 'e_gg': e_gg, 'H' : H, 'F1' : F1, 'F2' : F2, 'U' : U, 'Ua' : Ua ,'T' : T}
        return GP

    def AuthoritySetup(self, aid, GP):

        alpha = self.group.random(ZR)
        gamma = self.group.random(ZR)
        e_gg_alpha = GP['e_gg']**alpha
        g2_gamma = GP['g2']**gamma

        PK = {'e_gg_alpha': e_gg_alpha, 'g2_gamma': g2_gamma}
        SK = {'alpha': alpha, 'gamma': gamma}
        SKaid = {aid: SK}
        PKaid = {aid: PK}
        return PKaid, SKaid


    def keygen(self, gid, attr_list, SKaid, GP):
        """
        Generate a key for a set of attributes.
        """

        if debug:
            print('Key generation algorithm:\n')

        K1 = {}
        K2 = {}

        for attr in attr_list:
            aid = GP['T'][attr]
            t = self.group.random(ZR)
            alpha = SKaid[aid]['alpha']
            gamma = SKaid[aid]['gamma']
            K1_attr = (GP['g1']**alpha)*(GP['H'][gid]**gamma)*(GP['F1'][attr]**t)
            K1[attr] = K1_attr
            K2_attr = GP['g1']**t
            K2[attr] = K2_attr

        return {'attr_list': attr_list, 'K1': K1, 'K2': K2}

    def encrypt(self, PKaid, msg, policy_str, GP):
        """
         Encrypt a message M under a monotone span program.
        """

        if debug:
            print('Encryption algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        v = []
        for i in range(num_cols):
            rand = self.group.random(ZR)
            v.append(rand)
        z = v[0]    # shared secret

        w = []
        for i in range(num_cols):
            if i == 0:
                w.append(0)
                continue
            rand = self.group.random(ZR)
            w.append(rand)
        #print(w[0])

        e_gg = GP['e_gg']
        c0 = msg*(e_gg)**z

        C1 = {}
        C2 = {}
        C3 = {}
        C4 = {}

        for attr, row in mono_span_prog.items():

            cols = len(row)
            lambda_sum = 0
            omega_sum = 0
            for i in range(cols):
                lambda_sum += row[i] * v[i]
                omega_sum += row[i] * w[i]
            attr_stripped = self.util.strip_index(attr)
            e_gg_alpha = PKaid[GP['T'][attr_stripped]]['e_gg_alpha']
            t = self.group.random(ZR)
            g = GP['g2']

            c1_attr = (e_gg**lambda_sum) * (e_gg_alpha**t)
            c2_attr = g**(-t)
            c3_attr = (PKaid[GP['T'][attr_stripped]]['g2_gamma']**t)*(g**omega_sum)
            c4_attr = GP['F2'][attr]**t
            C1[attr] = c1_attr
            C2[attr] = c2_attr
            C3[attr] = c3_attr
            C4[attr] = c4_attr

        return {'policy': policy, 'c0': c0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4}

    def decrypt(self, gid, ctxt, key, GP):
        """
         Decrypt ciphertext ctxt with key key.
        """

        if debug:
            print('Decryption algorithm:\n')



        nodes = self.util.prune(ctxt['policy'], key['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return None

        prodG1 = 1
        prodG2 = 1
        prodG3 = 1
        prodG4 = 1

        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)
            prodG1 *= ctxt['C1'][attr]
            prodG2 *= pair(key['K1'][attr_stripped], ctxt['C2'][attr])
            prodG3 *= ctxt['C3'][attr]
            prodG4 *= pair(key['K2'][attr_stripped], ctxt['C4'][attr])

        return (ctxt['c0'] / (prodG1 * prodG2 * pair(GP['H'][gid],prodG3) * prodG4))
