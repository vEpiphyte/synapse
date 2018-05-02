import hashlib
import synapse.cortex as s_cortex

from synapse.tests.common import *


BITS = 2048
MODULUS = 21680073759901560171209957725353947845838657877489390985629011146485484841613254787012016412199394070769311374208089618561220933596407338770180192384317562523491504421019673615789668662137487867201848792175221628030748903758659512346089900598997888270904750957373405614508524979486643166681109379345160580296332322836921704829624843374764439692279358554558941230025781198901328474879152567953389671112502837567613909993840129753441530321638514598444958171485518879137004811038656035936398122093390552808567871935626042277760893618056402149399121098975363621174280972619512060731453783290243406423030552375052230477117
HEXSTR_MODULUS = 'abbd407f417fe8d6632aae1c6d09b271416bef9244e61f7c7c2856ddfde3ecf93cd50b3eaea5c9b8cb9bfb5a317bf50925ab500a06247ec2f3294891a8e62c317ee648f933ec1bf760a9d7e9a5ea4706b2a2c3f6376079114ddcc7a15d3fecf001458f22f0551802a25ef95cf464aabeb0514ea3849583bc09022730c44a2ff5f893fc6885add69c103d75114dd2f11436f617fbfb0af2978802aabf35483bbfcc470d50d6afb4283c1d06d2bf27efe9d7c09f226895633a46c3d77173bf0db8634299462b5f29629ad3b0470c76ddfd331ed0207d4dbd5fd44a2f66ca5f802ac0130e4a4bb2c149b5baa7a373188823ee21fe2950a76c818586919f7914453d'
PUBLIC_EXPONENT = 65537
HEXSTR_PUBLIC_EXPONENT = '10001'
PRIVATE_EXPONENT = 19908935091507935910766878035079064394252223126492576982286506520422599969830943022212554491896121784047323899994895364662251238943384391552951073718134547894338911005542319868457049133976538936963987760493787680848597910720774607191734874769206553699556901092018305233653761369004450092319898771337256804613522317422533116544949192149922930004965904101153270320899927630023151519164234033080401056920737409312210208519608126904153045420378101666974043300846024202376639976827675424610873439010403494045110511125497106688005087420608633713569510808521791875704919516380552984253009872506805233489422334428748712987077
HEXSTR_PRIVATE_EXPONENT = '9db58a80120f3b2b7d1f998a231b8f916fa985f4456f2a24f0033f5a56a7b35b61e0a695e65dfab3c7ceb2f0ad968e7bdaeac9f29a97730ce5add8a5627c14c3532c7880d88c8f56099f8ed65275a4c9e2cb93b70c3d7c904677639fac7962c537f5bfaf2f12859d0dacb7c403ee59da0922715bba0a6f5202d7c653833e39715f04664c2396c47bdf3f09f5486d8f6aea767ba011f1a5a10c8b57f079aea58abfd5e50ef20aa5e09b1082f6af98e806c9aeeb894148a7d82cd6e1443c6115eb567fba0eacf5b7178518b8ba312da6ace22238d1ed19f3e703652576a6152ba60d4d4c6bc75b3ee7c8efeadee0c5ed7c14bf2930a6c4f13137becf38912f49c5'
PRIVATE_PRIME_P = 156532994640717807361608570611796319305663234740664421762070081027284552113924902465098803666443018989500889191221784106739853246716130351638754811952418505918520952533734611708019313476414762006641033262124920543558854778066147079325885899480329140950654918462245144305556866163678471146913922858422171189943
HEXSTR_PRIVATE_PRIME_P = 'dee90ee63c12729a3fe7d38c581abf7e1c784ec0bd4bfdd1282286ea9996673942a24c7c98b31c6cd12db8ba96da785c4392569d7bfc2be9d9907c3b7fbf40d31891642952a0e5a23dfbe721a746588df9a246ea4936a1958f66fd3a32c08008a0f6ed9b516fa869fb08a57ef31c0ec217f173e489a2f8f111e25c25c961c2b7'
PRIVATE_PRIME_Q = 138501622674904590241979533901923672469392492154619678828180202352596319430957093632613282955184195992095035063297311252977898969555093667265836880501714630547665618115519694458795827169975578296162626726079027770594551438491027253477102905357276738700715758142905702644770884617741935638407118002466518037419
HEXSTR_PRIVATE_PRIME_Q = 'c53b9c8dfb3dda04d16c7f779a02b3b8c7b44bf876dc88ad562778eafaded9ade882ccfb887761515a251c224761bef7207fa489e398041787cfbd155f1034a207d517f06bc76a044262484f82f0c6a887f776b1dce837408999d88dd33a96c7f80e23719e77a11075d337bf9cc47d7dbf98e341b81c23f165dd15ccfd2973ab'
HEXSTR_RSA_KEY = 'abbd407f417fe8d6632aae1c6d09b271416bef9244e61f7c7c2856ddfde3ecf93cd50b3eaea5c9b8cb9bfb5a317bf50925ab500a06247ec2f3294891a8e62c317ee648f933ec1bf760a9d7e9a5ea4706b2a2c3f6376079114ddcc7a15d3fecf001458f22f0551802a25ef95cf464aabeb0514ea3849583bc09022730c44a2ff5f893fc6885add69c103d75114dd2f11436f617fbfb0af2978802aabf35483bbfcc470d50d6afb4283c1d06d2bf27efe9d7c09f226895633a46c3d77173bf0db8634299462b5f29629ad3b0470c76ddfd331ed0207d4dbd5fd44a2f66ca5f802ac0130e4a4bb2c149b5baa7a373188823ee21fe2950a76c818586919f7914453d/10001'

TEST_MD5 = hashlib.md5(b'test').hexdigest()
TEST_SHA1 = hashlib.sha1(b'test').hexdigest()
TEST_SHA256 = hashlib.sha256(b'test').hexdigest()
TEST_SHA384 = hashlib.sha384(b'test').hexdigest()
TEST_SHA512 = hashlib.sha512(b'test').hexdigest()

class CryptoModelTest(SynTest):

    def test_norm_lm_ntlm(self):
        with self.getTestCore() as core:  # type: s_cortex.Cortex
            lm = core.model.type('hash:lm')
            valu, subs = lm.norm(TEST_MD5.upper())
            self.eq(valu, TEST_MD5)
            self.eq(subs, {})
            self.raises(BadTypeValu, lm.norm, TEST_SHA256)

            ntlm = core.model.type('hash:ntlm')
            valu, subs = lm.norm(TEST_MD5.upper())
            self.eq(valu, TEST_MD5)
            self.eq(subs, {})
            self.raises(BadTypeValu, ntlm.norm, TEST_SHA256)

    def test_forms_crypto_simple(self):
        with self.getTestCore() as core:  # type: s_cortex.Cortex
            with core.xact(write=True) as xact:
                # md5
                node = xact.addNode('hash:md5', TEST_MD5.upper())
                self.eq(node.ndef, ('hash:md5', TEST_MD5))
                self.eq(node.props, {})
                self.raises(BadTypeValu, xact.addNode, 'hash:md5', TEST_SHA1)
                # sha1
                node = xact.addNode('hash:sha1', TEST_SHA1.upper())
                self.eq(node.ndef, ('hash:sha1', TEST_SHA1))
                self.eq(node.props, {})
                self.raises(BadTypeValu, xact.addNode, 'hash:sha1', TEST_SHA256)
                # sha256
                node = xact.addNode('hash:sha256', TEST_SHA256.upper())
                self.eq(node.ndef, ('hash:sha256', TEST_SHA256))
                self.eq(node.props, {})
                self.raises(BadTypeValu, xact.addNode, 'hash:sha256', TEST_SHA384)
                # sha384
                node = xact.addNode('hash:sha384', TEST_SHA384.upper())
                self.eq(node.ndef, ('hash:sha384', TEST_SHA384))
                self.eq(node.props, {})
                self.raises(BadTypeValu, xact.addNode, 'hash:sha384', TEST_SHA512)
                # sha512
                node = xact.addNode('hash:sha512', TEST_SHA512.upper())
                self.eq(node.ndef, ('hash:sha512', TEST_SHA512))
                self.eq(node.props, {})
                self.raises(BadTypeValu, xact.addNode, 'hash:sha512', TEST_MD5)

    def test_form_rsakey(self):
        prop = 'rsa:key'
        props = {
            'bits': BITS,
            'priv:exp': PRIVATE_EXPONENT,
            'priv:p': PRIVATE_PRIME_P,
            'priv:q': PRIVATE_PRIME_Q,
        }
        valu = (MODULUS, PUBLIC_EXPONENT)

        with self.getTestCore() as core:  # type: s_cortex.Cortex
            with core.xact(write=True) as xact:
                node = xact.addNode(prop, valu, props)
                node = node.pack()

        self.eq(node[1].get('ndef')[1], (HEXSTR_MODULUS, HEXSTR_PUBLIC_EXPONENT))
        nprops = node[1].get('props')
        self.eq(nprops.get('mod'), HEXSTR_MODULUS)
        self.eq(nprops.get('bits'), BITS)
        self.eq(nprops.get('pub:exp'), HEXSTR_PUBLIC_EXPONENT)
        self.eq(nprops.get('priv:exp'), HEXSTR_PRIVATE_EXPONENT)
        self.eq(nprops.get('priv:p'), HEXSTR_PRIVATE_PRIME_P)
        self.eq(nprops.get('priv:q'), HEXSTR_PRIVATE_PRIME_Q)
