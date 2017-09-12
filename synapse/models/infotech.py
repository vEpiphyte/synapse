from synapse.eventbus import on

import synapse.common as s_common

from synapse.lib.module import CoreModule

class ItMod(CoreModule):

    def initCoreModule(self):
        # ctors for
        self.core.addSeedCtor('it:sec:filehit:yara', self.seedFileHitGen(ruleform='it:sec:rule:yara'))
        self.core.addSeedCtor('it:sec:filehit:snort', self.seedFileHitGen(ruleform='it:sec:rule:snort'))

    def seedFileHitGen(self, ruleform):
        '''
        Seed constructor for building it:sec:filehit nodes from the
        intersection of file:bytes and it:sec:rule:* nodes.

        Args:
            ruleform:

        Returns:

        '''

        def seedFileHit(prop, valu, **props):
            valu, subs = self.core.getPropNorm(prop, valu)

            tufo = self.core.getTufoByProp(prop, valu)
            if tufo is not None:
                return tufo

            sig = subs.get('sig')

            rtufo = self.core.getTufoByProp(ruleform, sig)
            if not rtufo:
                raise s_common.BadTypeValu(mesg='Sig value is not the correct type.',
                                           type=ruleform, valu=sig)

            with self.core.getCoreXact() as xact:

                props.update(subs)

                tick = s_common.now()
                iden = s_common.guid()

                fulls, toadd = self.core._normTufoProps(prop, subs, isadd=True)
                self.core._addDefProps(prop, fulls)

                fulls[prop] = valu
                fulls['tufo:form'] = prop

                self.core.formed[prop] += 1

                self.core.fire('node:form', form=prop, valu=valu, props=fulls)

                rows = [(iden, p, v, tick) for (p, v) in fulls.items()]

                self.core.addRows(rows)

                tufo = (iden, fulls)

                if self.core.caching:
                    # avoid .new in cache
                    cachefo = (iden, dict(fulls))
                    for p, v in fulls.items():
                        self.core._bumpTufoCache(cachefo, p, None, v)

                # fire notification events
                xact.fire('node:add', form=prop, valu=valu, node=tufo)
                xact.spliced('node:add', form=prop, valu=valu, props=props)

                if self.core.autoadd:
                    self.core._runAutoAdd(toadd)

                tufo[1]['.new'] = True
                return tufo

        return seedFileHit

    @staticmethod
    def getBaseModels():
        modl = {
            'types': (
                ('it:host', {'subof': 'guid', 'doc': 'A GUID for a host/system'}),
                ('it:hostname', {'subof': 'str:lwr', 'doc': 'A system/host name'}),

                ('it:hosturl', {'subof': 'comp', 'fields': 'host,it:host|url,inet:url'}),

                ('it:sec:cve', {'subof': 'str:lwr', 'regex': '(?i)^CVE-[0-9]{4}-[0-9]{4,}$',
                                'doc': 'A CVE entry from Mitre'}),


                ('it:dev:str', {'subof': 'str', 'doc': 'A developer selected string'}),
                ('it:dev:int', {'subof': 'int', 'doc': 'A developer selected int constant'}),

                ('it:exec:proc', {'subof': 'guid', 'doc': 'A unique process execution on a host'}),
                ('it:exec:subproc', {'subof': 'comp', 'fields': 'proc=it:exec:proc,child=it:exec:proc'}),

                ('it:dev:pipe', {'subof': 'it:dev:str', 'doc': 'A  named pipe string'}),
                ('it:dev:mutex', {'subof': 'it:dev:str', 'doc': 'A named mutex string'}),
                ('it:dev:regkey', {'subof': 'it:dev:str', 'doc': 'A windows registry key string'}),

                ('it:dev:regval', {'subof': 'comp', 'fields': 'key=it:dev:regkey',
                                   'optfields': 'str=it:dev:str,int=it:dev:int,bytes=file:bytes',
                                   'doc': 'A windows registry key/val pair'}),
                ('it:av:sig',
                 {'subof': 'sepr', 'sep': '/', 'fields': 'org,ou:alias|sig,str:lwr', 'doc': 'An antivirus signature'}),
                ('it:av:filehit',
                 {'subof': 'sepr', 'sep': '/', 'fields': 'file,file:bytes|sig,it:av:sig', 'doc': 'An antivirus hit'}),

                ('it:sec:rule', {'subof': 'guid',
                                 'doc': 'A guid for storing the rule text of an arbitrary signature type.'}),
                ('it:sec:filehit', {'subof': 'comp', 'fields': 'file,file:bytes|sig,it:sec:rule',
                                    'doc': 'The interesection of a file and a arbitrary rule text.'}),

                ('it:sec:rule:snort:reference', {'subof': 'str',
                                                 'doc': 'Semicolon delimited list of Snort references',
                                                 'regex': r'^([\d\w]+,.*);'}),

            ),

            'forms': (

                ('it:host', {}, [
                    ('name', {'ptype': 'it:hostname', 'doc': 'Optional name for the host'}),
                    ('desc', {'ptype': 'str:txt', 'doc': 'Optional description of the host'}),

                    # FIXME we probably eventually need a bunch of stuff here...
                    ('ipv4', {'ptype': 'inet:ipv4', 'doc': 'Optional last known ipv4 address for the host'}),

                ]),

                ('it:hostname', {}, ()),

                ('it:sec:cve', {'ptype': 'it:sec:cve'}, [
                    ('desc', {'ptype': 'str'}),
                ]),

                ('it:av:sig', {'ptype': 'it:av:sig'}, [
                    ('sig', {'ptype': 'str:lwr'}),
                    ('org', {'ptype': 'ou:alias'}),
                    ('desc', {'ptype': 'str'}),
                    ('url', {'ptype': 'inet:url'}),
                ]),

                ('it:av:filehit', {'ptype': 'it:av:filehit'}, [
                    ('file', {'ptype': 'file:bytes'}),
                    ('sig', {'ptype': 'it:av:sig'}),
                ]),

                ('it:dev:str', {}, (
                    ('norm', {'ptype': 'str', 'ro': 1, 'lower': 1, 'doc': 'Lower case normalized version of it:dev:str'}),
                )),

                ('it:dev:int', {}, (
                )),

                ('it:dev:pipe', {}, ()),
                ('it:dev:mutex', {}, ()),
                ('it:dev:regkey', {}, ()),

                ('it:dev:regval', {}, (
                    ('key', {'ptype': 'it:dev:regkey', 'ro': 1}),
                    ('str', {'ptype': 'it:dev:str', 'ro': 1}),
                    ('int', {'ptype': 'it:dev:int', 'ro': 1}),
                    ('bytes', {'ptype': 'file:bytes', 'ro': 1}),
                )),

                ('it:exec:pipe', {'ptype': 'guid'}, (
                    ('time', {'ptype': 'time'}),
                    ('host', {'ptype': 'it:host'}),
                    ('name', {'ptype': 'it:dev:pipe'}),
                    ('proc', {'ptype': 'it:exec:proc'}),
                    ('exe', {'ptype': 'file:bytes', 'doc': 'The file containing code which created the pipe'}),
                )),

                ('it:exec:mutex', {'ptype': 'guid'}, (
                    ('time', {'ptype': 'time'}),
                    ('host', {'ptype': 'it:host'}),
                    ('name', {'ptype': 'it:dev:mutex'}),
                    ('proc', {'ptype': 'it:exec:proc'}),
                    ('exe', {'ptype': 'file:bytes', 'doc': 'The file containing code which created the mutex'}),
                )),

                ('it:exec:proc', {'ptype': 'guid'}, (
                    ('pid', {'ptype': 'int', 'doc': 'The process ID'}),
                    ('time', {'ptype': 'time', 'doc': 'The start time for the process'}),
                    ('host', {'ptype': 'it:host', 'doc': 'The host which executed the process'}),
                    ('user', {'ptype': 'inet:user', 'doc': 'The user name of the process owner'}),
                    ('exe', {'ptype': 'file:bytes', 'doc': 'The file considered the "main" executable for the process'}),
                    ('cmd', {'ptype': 'str', 'doc': 'The command string for the process'}),
                )),

                ('it:exec:subproc', {}, (
                    ('proc', {'ptype': 'it:exec:proc', 'doc': 'The parent process'}),
                    ('child', {'ptype': 'it:exec:proc', 'doc': 'The child process'}),
                    ('host', {'ptype': 'it:host', 'doc': 'The host which executed the process'}),
                )),

                ('it:exec:url', {'ptype': 'guid'}, (
                    ('url', {'ptype': 'inet:url'}),
                    ('host', {'ptype': 'it:host'}),
                    ('proc', {'ptype': 'it:exec:proc'}),
                    ('time', {'ptype': 'time'}),

                    ('exe', {'ptype': 'file:bytes', 'doc': 'The file containing code which retrieved the URL'}),
                    ('ipv4', {'ptype': 'inet:ipv4', 'doc': 'The IPv4 address of the host during URL retrieval'}),
                    ('ipv6', {'ptype': 'inet:ipv6', 'doc': 'The IPv6 address of the host during URL retrieval'}),
                )),

                ('it:exec:bind:tcp', {'ptype': 'guid'}, (
                    ('port', {'ptype': 'inet:port', 'doc': 'The bound TCP port'}),

                    ('ipv4', {'ptype': 'inet:ipv4', 'doc': 'The (optional) IPv4 specified to bind()'}),
                    ('ipv6', {'ptype': 'inet:ipv6', 'doc': 'The (optional) IPv6 specified to bind()'}),
                    ('host', {'ptype': 'it:host'}),
                    ('proc', {'ptype': 'it:exec:proc'}),
                    ('time', {'ptype': 'time'}),

                    ('exe', {'ptype': 'file:bytes', 'doc': 'The file containing code which bound the listener'}),
                )),

                ('it:exec:bind:udp', {'ptype': 'guid'}, (
                    ('port', {'ptype': 'inet:port', 'doc': 'The bound UDP port'}),

                    ('ipv4', {'ptype': 'inet:ipv4', 'doc': 'The (optional) IPv4 specified to bind()'}),
                    ('ipv6', {'ptype': 'inet:ipv6', 'doc': 'The (optional) IPv6 specified to bind()'}),
                    ('host', {'ptype': 'it:host'}),
                    ('proc', {'ptype': 'it:exec:proc'}),
                    ('time', {'ptype': 'time'}),

                    ('exe', {'ptype': 'file:bytes', 'doc': 'The file containing code which bound the listener'}),
                )),

                ('it:fs:file', {'ptype': 'guid'}, (
                    ('host', {'ptype': 'it:host'}),

                    ('path', {'ptype': 'file:path'}),
                    ('path:dir', {'ptype': 'file:path', 'ro': 1}),
                    ('path:ext', {'ptype': 'str:lwr', 'ro': 1}),
                    ('path:base', {'ptype': 'file:base', 'ro': 1}),
                    ('file', {'ptype': 'file:bytes'}),

                    ('ctime', {'ptype': 'time', 'doc': 'File creation time'}),
                    ('mtime', {'ptype': 'time', 'doc': 'File modification time'}),
                    ('atime', {'ptype': 'time', 'doc': 'File access time'}),

                    ('user', {'ptype': 'inet:user', 'doc': 'The owner of the file'}),
                    ('group', {'ptype': 'inet:user', 'doc': 'The group owner of the file'}),
                )),

                # FIXME seed for hex file bytes
                ('it:exec:file:add', {'ptype': 'guid'}, (
                    ('host', {'ptype': 'it:host'}),
                    ('path', {'ptype': 'file:path'}),
                    ('path:dir', {'ptype': 'file:path', 'ro': 1}),
                    ('path:ext', {'ptype': 'str:lwr', 'ro': 1}),
                    ('path:base', {'ptype': 'file:base', 'ro': 1}),
                    ('file', {'ptype': 'file:bytes'}),
                    ('time', {'ptype': 'time'}),
                    ('proc', {'ptype': 'it:exec:proc'}),
                    ('exe', {'ptype': 'file:bytes', 'doc': 'The file containing the code that created the file'}),

                )),

                ('it:exec:file:del', {'ptype': 'guid'}, (
                    ('host', {'ptype': 'it:host'}),
                    ('path', {'ptype': 'file:path'}),
                    ('path:dir', {'ptype': 'file:path', 'ro': 1}),
                    ('path:ext', {'ptype': 'str:lwr', 'ro': 1}),
                    ('path:base', {'ptype': 'file:base', 'ro': 1}),
                    ('file', {'ptype': 'file:bytes'}),
                    ('time', {'ptype': 'time'}),
                    ('proc', {'ptype': 'it:exec:proc'}),
                    ('exe', {'ptype': 'file:bytes', 'doc': 'The file containing the code that deleted the file'}),

                )),

                ('it:exec:file:read', {'ptype': 'guid'}, (
                    ('host', {'ptype': 'it:host'}),
                    ('path', {'ptype': 'file:path'}),
                    ('path:dir', {'ptype': 'file:path', 'ro': 1}),
                    ('path:ext', {'ptype': 'str:lwr', 'ro': 1}),
                    ('path:base', {'ptype': 'file:base', 'ro': 1}),
                    ('file', {'ptype': 'file:bytes'}),
                    ('time', {'ptype': 'time'}),
                    ('proc', {'ptype': 'it:exec:proc'}),
                    ('exe', {'ptype': 'file:bytes', 'doc': 'The file containing the code that read the file'}),

                )),

                ('it:exec:file:write', {'ptype': 'guid'}, (
                    ('host', {'ptype': 'it:host'}),
                    ('path', {'ptype': 'file:path'}),
                    ('path:dir', {'ptype': 'file:path', 'ro': 1}),
                    ('path:ext', {'ptype': 'str:lwr', 'ro': 1}),
                    ('path:base', {'ptype': 'file:base', 'ro': 1}),
                    ('file', {'ptype': 'file:bytes'}),
                    ('time', {'ptype': 'time'}),
                    ('proc', {'ptype': 'it:exec:proc'}),
                    ('exe', {'ptype': 'file:bytes', 'doc': 'The file containing the code that wrote to the file'}),

                )),

                ('it:exec:reg:get', {'ptype': 'guid'}, (
                    ('host', {'ptype': 'it:host'}),
                    ('reg', {'ptype': 'it:dev:regval'}),
                    ('reg:key', {'ptype': 'it:dev:regkey', 'ro': 1}),
                    ('reg:int', {'ptype': 'it:dev:int', 'ro': 1}),
                    ('reg:str', {'ptype': 'it:dev:str', 'ro': 1}),
                    ('reg:bytes', {'ptype': 'file:bytes', 'ro': 1}),
                    ('exe', {'ptype': 'file:bytes'}),
                    ('proc', {'ptype': 'it:exec:proc'}),
                    ('time', {'ptype': 'time'}),
                )),

                ('it:exec:reg:set', {'ptype': 'guid'}, (
                    ('host', {'ptype': 'it:host'}),
                    ('reg', {'ptype': 'it:dev:regval'}),
                    ('reg:key', {'ptype': 'it:dev:regkey', 'ro': 1}),
                    ('reg:int', {'ptype': 'it:dev:int', 'ro': 1}),
                    ('reg:str', {'ptype': 'it:dev:str', 'ro': 1}),
                    ('reg:bytes', {'ptype': 'file:bytes', 'ro': 1}),
                    ('exe', {'ptype': 'file:bytes'}),
                    ('proc', {'ptype': 'it:exec:proc'}),
                    ('time', {'ptype': 'time'}),
                )),

                ('it:exec:reg:del', {'ptype': 'guid'}, (
                    ('host', {'ptype': 'it:host'}),
                    ('reg', {'ptype': 'it:dev:regval'}),
                    ('reg:key', {'ptype': 'it:dev:regkey', 'ro': 1}),
                    ('reg:int', {'ptype': 'it:dev:int', 'ro': 1}),
                    ('reg:str', {'ptype': 'it:dev:str', 'ro': 1}),
                    ('reg:bytes', {'ptype': 'file:bytes', 'ro': 1}),
                    ('exe', {'ptype': 'file:bytes'}),
                    ('proc', {'ptype': 'it:exec:proc'}),
                    ('time', {'ptype': 'time'}),
                )),

                ('it:sec:rule:yara',
                 {'ptype': 'it:sec:rule', 'doc': 'YARA rule.'},
                 [
                    ('text', {'ptype': 'str', 'doc': 'The text of a YARA rule', 'ro': 1, 'req': 1}),
                    ('rev', {'ptype': 'int', 'doc': 'Rule revision', 'defval': -1}),
                    ('name', {'ptype': 'str', 'doc': 'Rule name'},)
                 ]
                 ),

                ('it:sec:filehit:yara',
                 {'ptype': 'it:sec:filehit', 'doc': 'YARA rule hit'},
                 [
                     ('file', {'ptype': 'file:bytes', 'ro': 1}),
                     # XXX There is no strict checking of the ptype ACTUALLY being a :rule:yara
                     # XXX This is an attempt to show specific forms made from generic types
                     # XXX To avoid form explosion for all the different rule types we could ever
                     # XXX Want to model in the futrue.
                     ('sig', {'ptype': 'it:sec:rule', 'ro': 1}),
                 ]
                 ),

                ('it:sec:rule:snort',
                 {'ptype': 'it:sec:rule', 'doc': 'Snort rule.'},
                 [
                     ('text', {'ptype': 'str', 'doc': 'The text of a Snort rule', 'ro': 1, 'req': 1}),
                     # Metadata from
                     # http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node31.html#SECTION00441000000000000000
                     ('rev', {'ptype': 'int', 'doc': 'Rule revision', 'defval': -1}),
                     ('msg', {'ptype': 'str', 'doc': 'Snort msg'},),
                     ('sid', {'ptype': 'int', 'doc': 'Snort Rule ID'}, ),
                     ('gid', {'ptype': 'int', 'doc': 'Snort Generator ID'},),

                     ('reference', {'ptype': 'it:sec:rule:snort:reference',
                                    'doc': 'Semicolon delimited list of Snort references',
                                    },),
                     ('classtype', {'ptype': 'str', 'doc': 'Snort classtype'},),
                     ('priority', {'ptype': 'int', 'doc': 'Snort Rule priority'},),
                 ]
                 ),

                ('it:sec:filehit:snort',
                 {'ptype': 'it:sec:filehit', 'doc': 'Snort rule hit'},
                 [
                     ('file', {'ptype': 'file:bytes', 'ro': 1}),
                     # XXX There is no strict checking of the ptype ACTUALLY being a :rule:snort
                     # XXX This is an attempt to show specific forms made from generic types
                     # XXX To avoid form explosion for all the different rule types we could ever
                     # XXX Want to model in the futrue.
                     ('sig', {'ptype': 'it:sec:rule', 'ro': 1}),
                 ]
                 ),

            ),

        }

        models = (
            ('it', modl),
        )

        return models

    def intiCoreModule(self):
        pass

    @on('node:form', form='it:dev:str')
    def _onFormItDevStr(self, mesg):
        props = mesg[1].get('props')
        props['it:dev:str:norm'] = mesg[1].get('valu').lower()
