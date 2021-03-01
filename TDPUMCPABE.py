#-*- coding: utf-8 -*-

'''

| Security Assumption: Decisional q-Parallel Bilinear Diffie-Hellman Exponent
|
| type:           ciphertext-policy attribute-based encryption
| setting:        Pairing
:Authors:         junwei
:Date:            7/2020
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP
import random
import hashlib

debug = False


class TDPUMCPABE(ABEnc):

    def __init__(self, group_obj, id_size, AA_size, uni_size, verbose=False):
        ABEnc.__init__(self)
        self.group = group_obj
        self.id_size = id_size #
        self.AA_size = AA_size #
        self.uni_size = uni_size  # bound on the size of the universe of attributes
        self.util = MSP(self.group, verbose)

    def H1(self):
        h1 = {}     #H1是将用户身份(gid)映射到G中元素
        for i in range(self.id_size):
            h1[i+1] = self.group.random(G1)
        return h1

    def H2(self):
        h2 = {}     #H2是将用户的属性映射到G中元素
        for i in range(self.uni_size):
            h2['A'+str(i+1)] = self.group.random(G1)
        return h2

    def T(self):
        t = {}      #T是将输入属性i映射到相应的授权机构aid
        for i in range(self.uni_size):
            t['A'+str(i+1)] = random.randint(1, self.AA_size)
        return t

    def setup(self, H1, H2, T):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('Setup algorithm:\n')

        # pick a random element each from two source groups and pair them
        g1 = self.group.random(G1)
        g2 = self.group.random(G2)
        e_gg = pair(g1, g2)


        PP = {'g1': g1, 'g2': g2, 'e_gg': e_gg, 'H1': H1, 'H2': H2, 'T': T}
        return PP

    def AuthoritySetup(self, aid, PP):

        alpha = self.group.random(ZR)
        beta = self.group.random(ZR)
        gamma = self.group.random(ZR)
        e_gg_alpha = PP['e_gg']**alpha
        g1_beta = PP['g1']**beta
        g1_gamma = PP['g1']**gamma
        g2_beta = PP['g2']**beta
        g2_gamma = PP['g2']**gamma

        PK = {'e_gg_alpha': e_gg_alpha, 'g1_beta': g1_beta, 'g1_gamma': g1_gamma, 'g2_beta': g2_beta, 'g2_gamma': g2_gamma}
        SK = {'alpha': alpha, 'beta': beta, 'gamma': gamma}
        SKaid = {aid: SK}
        PKaid = {aid: PK}
        return PKaid, SKaid


    def keygen(self, gid, attr_list, SKaid, PP):
        """
        Generate a key for a set of attributes.
        """

        if debug:
            print('Key generation algorithm:\n')



        u = PP['g1']**self.group.random(ZR)

        K1 = {}
        K2 = {}
        K3 = {}
        K4 = {}

        for attr in attr_list:
            aid = PP['T'][attr]
            alpha = SKaid[aid]['alpha']
            beta = SKaid[aid]['beta']
            gamma = SKaid[aid]['gamma']
            t = self.group.random(ZR)
            K1_attr = (PP['g1']**alpha)*(PP['H1'][gid]**beta)*(PP['H2'][attr]**t)*(u**(beta*(gid+gamma)))
            K2_attr = u**gamma
            K3_attr = u
            K4_attr = PP['g2']**t
            K1[attr] = K1_attr
            K2[attr] = K2_attr
            K3[attr] = K3_attr
            K4[attr] = K4_attr
        K5 = gid
        return {'attr_list': attr_list, 'K1': K1, 'K2': K2, 'K3': K3, 'K4': K4, 'K5': K5}

    def encrypt(self, PKaid, msg, policy_str, PP):
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
        s1 = v[0]    # shared secret

        u = []
        for i in range(num_cols):
            if i == 0:
                u.append(0)
                continue
            rand = self.group.random(ZR)
            u.append(rand)
        s2 = u[0]    # shared secret 0

        e_gg = PP['e_gg']
        c0 = msg*(e_gg)**s1

        C1 = {}
        C2 = {}
        C3 = {}
        C4 = {}
        C5 = {}
        for attr, row in mono_span_prog.items():

            cols = len(row)
            lambda_sum = 0
            omega_sum = 0
            for i in range(cols):
                lambda_sum += row[i] * v[i]
                omega_sum += row[i] * u[i]
            attr_stripped = self.util.strip_index(attr)
            r_attr = self.group.random(ZR)

            e_gg_alpha = PKaid[PP['T'][attr_stripped]]['e_gg_alpha']
            g2_beta = PKaid[PP['T'][attr_stripped]]['g2_beta']
            g = PP['g1']
            g2 = PP['g2']
            c1_attr = (e_gg**lambda_sum) * (e_gg_alpha**r_attr)
            c2_attr = g2**omega_sum
            c3_attr = g2_beta**r_attr
            c4_attr = PP['H2'][attr]**r_attr
            c5_attr = 1/g2**r_attr
            C1[attr] = c1_attr
            C2[attr] = c2_attr
            C3[attr] = c3_attr
            C4[attr] = c4_attr
            C5[attr] = c5_attr

        return {'policy': policy, 'c0': c0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4, 'C5': C5}

    def decrypt(self, ctxt, key, PP):
        """
         Decrypt ciphertext ctxt with key key.
        """

        if debug:
            print('Decryption algorithm:\n')



        nodes = self.util.prune(ctxt['policy'], key['attr_list'])
        if not nodes:
            print ("Policy not satisfied.")
            return None

        e_gg = PP['e_gg']

        prodG1 = 1
        prodG2 = 1
        prodG3 = 1
        prodG4 = 1
        prodG5 = 1

        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)
            prodG1 *= ctxt['C1'][attr]
            prodG2 *= ctxt['C2'][attr]*ctxt['C3'][attr]
            prodG3 *= pair(key['K2'][attr_stripped]*(key['K3'][attr_stripped])**key['K5'], ctxt['C3'][attr])
            prodG4 *= pair(ctxt['C4'][attr], key['K4'][attr_stripped])
            prodG5 *= pair(key['K1'][attr_stripped], ctxt['C5'][attr])

        return (ctxt['c0'] / (prodG1 * pair(PP['H1'][key['K5']],prodG2) * prodG3 * prodG4 * prodG5))
