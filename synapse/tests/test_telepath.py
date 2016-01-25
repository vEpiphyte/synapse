import time
import unittest

import synapse.link as s_link
import synapse.async as s_async
import synapse.daemon as s_daemon
#import synapse.session as s_session
import synapse.eventbus as s_eventbus
import synapse.telepath as s_telepath

from synapse.tests.common import *

class Foo:

    def bar(self, x, y):
        return x + y

    def baz(self, x, y):
        raise Exception('derp')

    def speed(self):
        return

    #def get(self, prop):
        #return s_session.current().get(prop)

    #def set(self, prop, valu):
        #return s_session.current().set(prop,valu)

class TelePathTest(SynTest):

    def getFooServ(self):
        dmon = s_daemon.Daemon()

        link = dmon.listen('tcp://127.0.0.1:0/foo')
        dmon.share('foo',Foo())

        return dmon,link

    def getFooEnv(self, url='tcp://127.0.0.1:0/foo'):
        env = TestEnv()
        env.add('dmon', s_daemon.Daemon(), fini=True)
        env.add('link', env.dmon.listen(url))

        env.dmon.share('foo',Foo())
        return env

    def test_telepath_basics(self):

        env = self.getFooEnv()

        foo = s_telepath.openlink(env.link)

        s = time.time()
        for i in range(1000):
            foo.speed()

        e = time.time()

        #print('TIME: %r' % ((e - s),))

        # ensure perf is still good...

        # FIXME: disabled due to travisci boxes
        #self.assertTrue( (e - s) < 0.5 )

        self.assertEqual( foo.bar(10,20), 30 )
        self.assertRaises( JobErr, foo.faz, 10, 20 )
        self.assertRaises( JobErr, foo.baz, 10, 20 )

        foo.fini()
        env.fini()

    def test_telepath_chop(self):

        dmon,link = self.getFooServ()

        port = link[1].get('port')

        foo = s_telepath.openurl('tcp://localhost:%d/foo' % (port,))

        self.assertEqual( foo.bar(10,20), 30 )

        foo.fini()
        dmon.fini()

    def test_telepath_nosuchobj(self):
        dmon,link = self.getFooServ()
        port = link[1].get('port')

        newp = s_telepath.openurl('tcp://localhost:%d/newp' % (port,))
        self.assertRaises( JobErr, newp.foo )

        dmon.fini()

    #def test_telepath_sess(self):
        #dmon,link = self.getFooServ()
        #port = link[1].get('port')

        #foo = s_telepath.openurl('tcp://localhost:%d/foo' % (port,))

        #self.assertIsNone( foo.get('woot') )

        #foo.set('woot',10)

        #self.assertEqual( foo.get('woot'), 10 )

        #foo.fini()
        #dmon.fini()

    def test_telepath_call(self):
        dmon,link = self.getFooServ()

        foo = s_telepath.openlink(link)

        job = foo.call('bar', 10, 20)
        self.assertIsNotNone( job )

        self.assertEqual( foo.sync(job), 30 )

        foo.fini()
        dmon.fini()

    def test_telepath_pki(self):
        env = self.getFooEnv(url='tcp://127.0.0.1:0/foo?pki=1')
        port = env.link[1].get('port')

        pki = env.dmon.pki # steal his...

        user = pki.genUserToken('visi',bits=512)
        host = pki.genHostToken('127.0.0.1',bits=512)
        root = pki.genUserToken('root', bits=512, root=True)

        pki.genTokenCert(user, signas=root[0])
        pki.genTokenCert(host, signas=root[0])

        #prox = s_telepath.openurl('tcp://localhost/foo?pki=1', port=port, pkistor=pki)
        prox = s_telepath.openurl('tcp://127.0.0.1/foo?pki=1', port=port, pkistor=pki)
        self.assertEqual( prox.bar(10,20), 30 )

        env.fini()

    def test_telepath_pki_nocert(self):
        env = self.getFooEnv(url='tcp://127.0.0.1:0/foo?pki=1')
        port = env.link[1].get('port')
        self.assertRaises( s_async.JobErr, s_telepath.openurl, 'tcp://127.0.0.1/foo', port=port )
        env.fini()

    def test_telepath_push(self):
        env = self.getFooEnv()
        port = env.link[1].get('port')

        prox0 = s_telepath.openurl('tcp://127.0.0.1/', port=port)
        prox0.push('foo1', Foo() )

        prox1 = s_telepath.openurl('tcp://127.0.0.1/foo1', port=port)

        self.eq( prox1.bar(10,20), 30 )

        prox0.fini()

        self.assertRaises( s_async.JobErr, prox1.bar, 10, 20 )

        prox1.fini()

        env.fini()

    def test_telepath_callx(self):

        class Baz:
            def faz(self, x, y=10):
                return '%d:%d' % (x,y)

        env = self.getFooEnv()
        env.dmon.share('baz', Baz())

        port = env.link[1].get('port')
        foo = s_telepath.openurl('tcp://127.0.0.1/foo', port=port)

        # make sure proxy is working normally...
        self.assertEqual( foo.bar(10,20), 30 )

        # carry out a cross item task
        job = foo.callx( 'baz', ('faz', (30,), {'y':40}), )

        self.assertEqual( foo.sync(job), '30:40' )

    def test_telepath_fakesync(self):
        env = self.getFooEnv()
        port = env.link[1].get('port')

        class DeadLock(s_eventbus.EventBus):

            def hork(self):
                self.fire('foo:bar')

            def bar(self, x, y):
                return x + y

        dead = DeadLock()
        env.dmon.share('dead',dead)

        data = {}
        evt = threading.Event()

        prox = s_telepath.openurl('tcp://127.0.0.1/dead', port=port)
        def foobar(mesg):
            data['foobar'] = prox.bar(10,20)
            evt.set()

        prox.on('foo:bar', foobar)

        prox.hork()

        evt.wait(timeout=2)

        self.assertEqual( data.get('foobar'), 30 )

        prox.fini()
        dead.fini()
        env.fini()
