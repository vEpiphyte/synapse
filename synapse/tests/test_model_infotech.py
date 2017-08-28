
from synapse.tests.common import *

def initcomp(*args, **kwargs):
    retn = list(args)
    retn.extend(kwargs.items())
    return retn

class InfoTechTest(SynTest):

    def test_model_infotech_host(self):
        with s_cortex.openurl('ram:///') as core:
            core.setConfOpt('enforce', 1)
            node = core.formTufoByProp('it:host', guid())
            self.nn(node)
            self.nn(node[1].get('it:host'))

    def test_model_infotech_cve(self):
        with s_cortex.openurl('ram:///') as core:
            core.setConfOpt('enforce', 1)

            node = core.formTufoByProp('it:sec:cve', 'CVE-2013-9999', desc='This is a description')
            self.nn(node)
            self.eq(node[1].get('it:sec:cve'), 'cve-2013-9999')
            self.eq(node[1].get('it:sec:cve:desc'), 'This is a description')
            self.raises(BadTypeValu, core.formTufoByProp, 'it:sec:cve', 'dERP')

            node = core.formTufoByProp('it:sec:cve', 'Cve-2014-1234567890', desc='This is a description')
            self.nn(node)
            self.eq(node[1].get('it:sec:cve'), 'cve-2014-1234567890')
            self.eq(node[1].get('it:sec:cve:desc'), 'This is a description')

    def test_model_infotech_av(self):
        with s_cortex.openurl('ram:///') as core:
            core.setConfOpt('enforce', 1)
            bytesguid = '1234567890ABCDEFFEDCBA0987654321'
            orgname = 'Foo'
            signame = 'Bar.BAZ.faZ'
            valu = (bytesguid, (orgname, signame))

            tufo = core.formTufoByProp('it:av:filehit', valu)
            self.eq(tufo[1].get('it:av:filehit:sig'), 'foo/bar.baz.faz')
            self.eq(tufo[1].get('it:av:filehit:file'), '1234567890abcdeffedcba0987654321')

            tufo = core.getTufoByProp('it:av:sig', 'foo/bar.baz.faz')
            self.eq(tufo[1].get('it:av:sig'), 'foo/bar.baz.faz')
            self.eq(tufo[1].get('it:av:sig:org'), 'foo')
            self.eq(tufo[1].get('it:av:sig:sig'), 'bar.baz.faz')

            tufo = core.getTufoByProp('ou:alias', 'foo')
            self.eq(tufo, None) # ou:alias will not be automatically formed at this time

    def test_model_infotech_hostname(self):

        with s_cortex.openurl('ram:///') as core:
            core.setConfOpt('enforce', 1)

            node = core.formTufoByProp('it:host', None, name='hehehaha')
            self.nn(node)
            self.eq(node[1].get('it:host:name'), 'hehehaha')

            node = core.getTufoByProp('it:hostname', 'hehehaha')
            self.nn(node)

    def test_model_infotech_filepath(self):

        with s_cortex.openurl('ram:///') as core:

            core.setConfOpt('enforce', 1)

            node = core.formTufoByProp('file:path', '/Foo/Bar/Baz.exe')

            self.nn(node)
            self.eq(node[1].get('file:path:dir'), '/foo/bar')
            self.eq(node[1].get('file:path:ext'), 'exe')
            self.eq(node[1].get('file:path:base'), 'baz.exe')

            node = core.getTufoByProp('file:path', '/foo')

            self.nn(node)
            self.none(node[1].get('file:path:ext'))

            self.eq(node[1].get('file:path:dir'), '')
            self.eq(node[1].get('file:path:base'), 'foo')

            node = core.formTufoByProp('file:path', r'c:\Windows\system32\Kernel32.dll')

            self.nn(node)
            self.eq(node[1].get('file:path:dir'), 'c:/windows/system32')
            self.eq(node[1].get('file:path:ext'), 'dll')
            self.eq(node[1].get('file:path:base'), 'kernel32.dll')

            self.nn(core.getTufoByProp('file:base', 'kernel32.dll'))

            node = core.getTufoByProp('file:path', 'c:')

            self.nn(node)
            self.none(node[1].get('file:path:ext'))
            self.eq(node[1].get('file:path:dir'), '')
            self.eq(node[1].get('file:path:base'), 'c:')

            node = core.formTufoByProp('file:path', r'/foo////bar/.././baz.json')

            self.nn(node)
            self.eq(node[1].get('file:path'), '/foo/baz.json')

    def test_model_infotech_itdev(self):

        # This tests not only the snort form but also the seed ctor as well

        with s_cortex.openurl('ram:///') as core:
            core.setConfOpt('enforce', 1)

            node = core.formTufoByProp('it:dev:str', 'He He Ha Ha')
            self.nn(node)
            self.eq(node[1].get('it:dev:str'), 'He He Ha Ha')
            self.eq(node[1].get('it:dev:str:norm'), 'he he ha ha')

            node = core.formTufoByProp('it:dev:pipe', 'mypipe')
            self.eq(node[1].get('it:dev:pipe'), 'mypipe')
            self.nn(core.getTufoByProp('it:dev:str', 'mypipe'))

            node = core.formTufoByProp('it:dev:mutex', 'mymutex')
            self.eq(node[1].get('it:dev:mutex'), 'mymutex')
            self.nn(core.getTufoByProp('it:dev:str', 'mymutex'))

            node = core.formTufoByProp('it:dev:regkey', 'myregkey')
            self.eq(node[1].get('it:dev:regkey'), 'myregkey')
            self.nn(core.getTufoByProp('it:dev:str', 'myregkey'))

            node = core.eval(r'[ it:dev:regval=("HKEY_LOCAL_MACHINE\\Foo\\Bar", str=hehe) ]')[0]
            self.eq(node[1].get('it:dev:regval:key'), r'HKEY_LOCAL_MACHINE\Foo\Bar')
            self.eq(node[1].get('it:dev:regval:str'), 'hehe')

            node = core.eval(r'[ it:dev:regval=("HKEY_LOCAL_MACHINE\\Foo\\Bar", int=20) ]')[0]
            self.eq(node[1].get('it:dev:regval:key'), r'HKEY_LOCAL_MACHINE\Foo\Bar')
            self.eq(node[1].get('it:dev:regval:int'), 20)

            iden = guid()
            node = core.eval(r'[ it:dev:regval=("HKEY_LOCAL_MACHINE\\Foo\\Bar", bytes=%s) ]' % iden)[0]
            self.eq(node[1].get('it:dev:regval:key'), r'HKEY_LOCAL_MACHINE\Foo\Bar')
            self.eq(node[1].get('it:dev:regval:bytes'), iden)

    def test_model_infotech_hostexec(self):

        with s_cortex.openurl('ram:///') as core:
            core.setConfOpt('enforce', 1)

            exe = guid()
            port = 80
            tick = now()
            host = guid()
            proc = guid()
            file = guid()
            ipv4 = 0x01020304
            ipv6 = 'ff::1'
            srv4 = (0x010203040 << 16) + port
            path = r'c:\Windows\System32\rar.exe'
            norm = r'c:/windows/system32/rar.exe'

            core.formTufoByProp('it:host', host)
            core.formTufoByProp('file:bytes', exe)

            # host execution process model
            #core.formTufoByProp('it:exec:proc',
            node = core.formTufoByProp('it:exec:proc', proc, pid=20, time=tick, host=host, user='visi', exe=exe)
            self.eq(node[1].get('it:exec:proc:exe'), exe)
            self.eq(node[1].get('it:exec:proc:pid'), 20)
            self.eq(node[1].get('it:exec:proc:time'), tick)
            self.eq(node[1].get('it:exec:proc:host'), host)
            self.eq(node[1].get('it:exec:proc:user'), 'visi')

            p0 = guid()
            p1 = guid()

            node = core.formTufoByProp('it:exec:subproc', (p0, p1), host=host)
            self.eq(node[1].get('it:exec:subproc:proc'), p0)
            self.eq(node[1].get('it:exec:subproc:child'), p1)
            self.eq(node[1].get('it:exec:subproc:host'), host)

            node = core.formTufoByProp('it:exec:mutex', '*', host=host, exe=exe, proc=proc, time=tick)
            self.eq(node[1].get('it:exec:mutex:exe'), exe)
            self.eq(node[1].get('it:exec:mutex:host'), host)
            self.eq(node[1].get('it:exec:mutex:proc'), proc)

            node = core.formTufoByProp('it:exec:pipe', '*', host=host, exe=exe, proc=proc, time=tick)
            self.eq(node[1].get('it:exec:pipe:exe'), exe)
            self.eq(node[1].get('it:exec:pipe:host'), host)
            self.eq(node[1].get('it:exec:pipe:proc'), proc)

            node = core.formTufoByProp('it:exec:file:add', '*', host=host, path=path, file=file, exe=exe, proc=proc, time=tick)
            self.eq(node[1].get('it:exec:file:add:exe'), exe)
            self.eq(node[1].get('it:exec:file:add:host'), host)
            self.eq(node[1].get('it:exec:file:add:proc'), proc)
            self.eq(node[1].get('it:exec:file:add:file'), file)
            self.eq(node[1].get('it:exec:file:add:path'), norm)

            node = core.formTufoByProp('it:exec:file:del', '*', host=host, path=path, file=file, exe=exe, proc=proc, time=tick)
            self.eq(node[1].get('it:exec:file:del:exe'), exe)
            self.eq(node[1].get('it:exec:file:del:host'), host)
            self.eq(node[1].get('it:exec:file:del:proc'), proc)
            self.eq(node[1].get('it:exec:file:del:file'), file)
            self.eq(node[1].get('it:exec:file:del:path'), norm)
            self.eq(node[1].get('it:exec:file:del:time'), tick)

            node = core.formTufoByProp('it:exec:bind:tcp', '*', host=host, port=port, ipv4=ipv4, ipv6=ipv6, exe=exe, proc=proc, time=tick)
            self.eq(node[1].get('it:exec:bind:tcp:exe'), exe)
            self.eq(node[1].get('it:exec:bind:tcp:host'), host)
            self.eq(node[1].get('it:exec:bind:tcp:port'), port)
            self.eq(node[1].get('it:exec:bind:tcp:ipv4'), ipv4)
            self.eq(node[1].get('it:exec:bind:tcp:ipv6'), ipv6)
            self.eq(node[1].get('it:exec:bind:tcp:proc'), proc)
            self.eq(node[1].get('it:exec:bind:tcp:time'), tick)

            node = core.formTufoByProp('it:exec:bind:udp', '*', host=host, port=port, ipv4=ipv4, ipv6=ipv6, exe=exe, proc=proc, time=tick)
            self.eq(node[1].get('it:exec:bind:udp:exe'), exe)
            self.eq(node[1].get('it:exec:bind:udp:host'), host)
            self.eq(node[1].get('it:exec:bind:udp:port'), port)
            self.eq(node[1].get('it:exec:bind:udp:ipv4'), ipv4)
            self.eq(node[1].get('it:exec:bind:udp:ipv6'), ipv6)
            self.eq(node[1].get('it:exec:bind:udp:proc'), proc)
            self.eq(node[1].get('it:exec:bind:udp:time'), tick)

            regval = initcomp('foo/bar', int=20)
            node = core.formTufoByProp('it:exec:reg:del', '*', host=host, reg=regval, exe=exe, proc=proc, time=tick)
            self.eq(node[1].get('it:exec:reg:del:reg:int'), 20)
            self.eq(node[1].get('it:exec:reg:del:reg:key'), 'foo/bar')
            self.eq(node[1].get('it:exec:reg:del:exe'), exe)
            self.eq(node[1].get('it:exec:reg:del:host'), host)
            self.eq(node[1].get('it:exec:reg:del:proc'), proc)
            self.eq(node[1].get('it:exec:reg:del:time'), tick)

            regval = initcomp('foo/bar', str='hehe')
            node = core.formTufoByProp('it:exec:reg:set', '*', host=host, reg=regval, exe=exe, proc=proc, time=tick)
            self.eq(node[1].get('it:exec:reg:set:reg:str'), 'hehe')
            self.eq(node[1].get('it:exec:reg:set:reg:key'), 'foo/bar')
            self.eq(node[1].get('it:exec:reg:set:exe'), exe)
            self.eq(node[1].get('it:exec:reg:set:host'), host)
            self.eq(node[1].get('it:exec:reg:set:proc'), proc)
            self.eq(node[1].get('it:exec:reg:set:time'), tick)

            regval = initcomp('foo/bar', int=20)
            node = core.formTufoByProp('it:exec:reg:get', '*', host=host, reg=regval, exe=exe, proc=proc, time=tick)
            self.eq(node[1].get('it:exec:reg:get:reg:int'), 20)
            self.eq(node[1].get('it:exec:reg:get:reg:key'), 'foo/bar')
            self.eq(node[1].get('it:exec:reg:get:exe'), exe)
            self.eq(node[1].get('it:exec:reg:get:host'), host)
            self.eq(node[1].get('it:exec:reg:get:proc'), proc)
            self.eq(node[1].get('it:exec:reg:get:time'), tick)

    def test_model_infotech_yara(self):
        with s_cortex.openurl('ram:///') as core:
            core.setConfOpt('enforce', 1)

            t0 = core.formTufoByProp('it:sec:rule:yara', '*',
                                     text='Some rule goes here.',
                                     name='FindPennywise',
                                     rev=0)

            self.nn(t0)
            self.eq(t0[1].get('it:sec:rule:yara:text'), 'Some rule goes here.')
            self.eq(t0[1].get('it:sec:rule:yara:name'), 'FindPennywise')
            self.eq(t0[1].get('it:sec:rule:yara:rev'), 0)

            t1 = core.formTufoByProp('it:sec:rule:yara', '*',
                                     text='Some rule goes here.')
            self.nn(t1)
            self.ne(t0[0], t1[0])
            self.notin('it:sec:rule:yara:name', t1[1])
            self.eq(t1[1].get('it:sec:rule:yara:rev'), -1)

            fileguid = guid()
            fnode = core.formTufoByProp('file:bytes', fileguid)
            self.nn(fnode)

            h0 = core.formTufoByProp('it:sec:filehit:yara', [fileguid,
                                                             t0[1].get('it:sec:rule:yara')]
                                     )
            self.nn(h0)
            self.eq(h0[1].get('it:sec:filehit:yara:sig'), t0[1].get('it:sec:rule:yara'))
            self.eq(h0[1].get('it:sec:filehit:yara:file'), fileguid)
            self.true(h0[1].get('.new'))

            h0_g = core.formTufoByProp('it:sec:filehit:yara', [fileguid,
                                                              t0[1].get('it:sec:rule:yara')])
            self.eq(h0[0], h0_g[0])
            self.false(h0_g[1].get('.new'))

            # We can pivot from a rule to a filehit
            nodes = core.eval('guid({}) pivot(it:sec:filehit:yara:sig)'.format(t0[0]))
            self.eq(len(nodes), 1)
            node = nodes[0]
            self.eq(h0[0], node[0])

            # We can pivot from a filehit to a file
            nodes = core.eval('guid({}) pivot(:file, file:bytes)'.format(h0[0]))
            self.eq(len(nodes), 1)
            node = nodes[0]
            self.eq(fnode[0], node[0])

            s0 = core.formTufoByProp('it:sec:rule:snort', '*',
                                     text='Some rule goes here.',
                                     )

            # Ensure we cannot form a it:sec:filehit:yara from a snort rule
            # b/c of the ctor's
            self.raises(BadTypeValu,
                        core.formTufoByProp,
                        'it:sec:filehit:yara',
                        [fileguid, s0[1].get('it:sec:rule:snort')]
                        )

            # Ensure we form file bytes nodes if someone hands us a file:bytes guid
            iden = guid()
            hf0 = core.formTufoByProp('it:sec:filehit:yara', [iden,
                                                             t0[1].get('it:sec:rule:yara')]
                                     )
            self.nn(hf0)
            self.eq(hf0[1].get('it:sec:filehit:yara:sig'), t0[1].get('it:sec:rule:yara'))
            self.eq(hf0[1].get('it:sec:filehit:yara:file'), iden)

            # Ensure cache behavior of the seed ctor is covered by tests
            core.setConfOpt('caching', 1)
            iden2 = guid()
            hf1 = core.formTufoByProp('it:sec:filehit:yara', [iden2,
                                                             t0[1].get('it:sec:rule:yara')]
                                     )
            self.nn(hf1)
            self.eq(hf1[1].get('it:sec:filehit:yara:sig'), t0[1].get('it:sec:rule:yara'))
            self.eq(hf1[1].get('it:sec:filehit:yara:file'), iden2)

    def test_model_infotech_snort(self):
        with s_cortex.openurl('ram:///') as core:
            core.setConfOpt('enforce', 1)

            s0 = core.formTufoByProp('it:sec:rule:snort', '*',
                                     text='Some rule goes here.',
                                     sid=1000001,
                                     rev=0,
                                     msg='I am a message!',
                                     gid=0xdeadb33f,
                                     reference='bugtraq,1387;',
                                     classtype='unknown',
                                     priority=1)

            self.nn(s0)
            self.eq(s0[1].get('it:sec:rule:snort:text'), 'Some rule goes here.')
            self.eq(s0[1].get('it:sec:rule:snort:sid'), 1000001)
            self.eq(s0[1].get('it:sec:rule:snort:rev'), 0)
            self.eq(s0[1].get('it:sec:rule:snort:msg'), 'I am a message!')
            self.eq(s0[1].get('it:sec:rule:snort:reference'), 'bugtraq,1387;')
            self.eq(s0[1].get('it:sec:rule:snort:classtype'), 'unknown')
            self.eq(s0[1].get('it:sec:rule:snort:priority'), 1)

            # Good reference valus
            valu, subs = core.getPropNorm('it:sec:rule:snort:reference', 'arachnids,IDS287; bugtraq,1387;')
            self.nn(valu)
            self.eq(len(subs), 0)
            valu, subs = core.getPropNorm('it:sec:rule:snort:reference', 'arachnids,IDS287; bugtraq,1387; cve,CAN-2000-1574;')
            self.nn(valu)
            self.eq(len(subs), 0)
            ref = 'url,manual-snort-org.s3-website-us-east-1.amazonaws.com/node31.html#SECTION00442000000000000000;'
            valu, subs = core.getPropNorm('it:sec:rule:snort:reference', ref)
            self.nn(valu)
            self.eq(len(subs), 0)
            valu, subs = core.getPropNorm('it:sec:rule:snort:reference', 'arachnids,IDS287; bugtraq,1387; cve,CAN-2000-1574;')
            self.nn(valu)
            self.eq(len(subs), 0)

            # Bad  reference valus
            self.raises(BadTypeValu, core.getPropNorm, 'it:sec:rule:snort:reference', 'lol')
            self.raises(BadTypeValu, core.getPropNorm, 'it:sec:rule:snort:reference', ' bugtraq,1387; ')
            self.raises(BadTypeValu, core.getPropNorm, 'it:sec:rule:snort:reference',
                        'i am a string, but not delimted until now;')

            # Defval

            s1 = core.formTufoByProp('it:sec:rule:snort', '*',
                                     text='Some other rule goes here.',
                                     )

            self.nn(s1)
            self.eq(s1[1].get('it:sec:rule:snort:text'), 'Some other rule goes here.')
            self.eq(s1[1].get('it:sec:rule:snort:rev'), -1)

            fileguid = guid()
            fnode = core.formTufoByProp('file:bytes', fileguid)
            self.nn(fnode)

            h0 = core.formTufoByProp('it:sec:filehit:snort', [fileguid,
                                                              s0[1].get('it:sec:rule:snort')]
                                     )
            self.nn(h0)
            self.eq(h0[1].get('it:sec:filehit:snort:sig'), s0[1].get('it:sec:rule:snort'))
            self.eq(h0[1].get('it:sec:filehit:snort:file'), fileguid)
            self.true(h0[1].get('.new'))
