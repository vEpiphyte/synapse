import shlex
import argparse

class Parser(argparse.ArgumentParser):

    def __init__(self, prog=None, descr=None):

        self.printf = None
        self.exited = False

        argparse.ArgumentParser.__init__(self,
            prog=prog,
            description=descr,
            formatter_class=argparse.RawDescriptionHelpFormatter)

    def exit(self, *args, **kwargs):
        # yea....  newp.
        self.exited = True

    def _print_message(self, text, fd=None):

        if self.printf is None:
            return

        for line in text.split('\n'):
            self.printf(line)

class Cmd:
    '''
    A one line description of the command.

    Command usage details and long form description.

    Example:

        cmd --help
    '''
    name = 'cmd'

    def __init__(self, text):
        self.opts = None
        self.text = text
        self.argv = self.getCmdArgv()
        self.pars = self.getArgParser()

    @classmethod
    def getCmdBrief(clas):
        return clas.__doc__.strip().split('\n')[0]

    def getCmdArgv(self):
        return shlex.split(self.text)

    def getArgParser(self):
        return Parser(prog=self.name, descr=self.__class__.__doc__)

    def reqValidOpts(self, snap):
        self.pars.printf = snap.printf
        self.opts = self.pars.parse_args(self.argv)
        return self.pars.exited

    def runStormCmd(self, snap, genr):
        yield from genr

class HelpCmd(Cmd):
    '''
    List available commands and a brief description for each.
    '''
    name = 'help'

    def getArgParser(self):
        pars = Cmd.getArgParser(self)
        pars.add_argument('command', nargs='?', help='Show the help output for a given command.')
        return pars

    def runStormCmd(self, snap, genr):

        yield from genr

        if not self.opts.command:
            for name, ctor in sorted(snap.core.getStormCmds()):
                snap.printf('%.20s: %s' % (name, ctor.getCmdBrief()))

        snap.printf('')
        snap.printf('For detailed help on any command, use <cmd> --help')

class LimitCmd(Cmd):
    '''
    Limit the number of nodes generated by the query in the given position.

    Example:

        inet:ipv4 | limit 10
    '''

    name = 'limit'

    def getArgParser(self):
        pars = Cmd.getArgParser(self)
        pars.add_argument('count', type=int, help='The maximum number of nodes to yield.')
        return pars

    def runStormCmd(self, snap, genr):

        for count, item in enumerate(genr):

            if count >= self.opts.count:
                snap.printf(f'limit reached: {self.opts.count}')
                break

            yield item

class UniqCmd(Cmd):
    '''
    Filter nodes by their uniq iden values.
    When this is used a Storm pipeline, only the first instance of a
    given node is allowed through the pipeline.

    Examples:

        #badstuff +inet:ipv4 ->* | uniq

    '''

    name = 'uniq'

    def getArgParser(self):
        pars = Cmd.getArgParser(self)
        return pars

    def runStormCmd(self, snap, genr):
        buidset = set()
        for node, path in genr:
            if node.buid in buidset:
                continue
            buidset.add(node.buid)
            yield node, path

class DelNodeCmd(Cmd):
    '''
    Delete nodes produced by the previous query logic.

    (no nodes are returned)

    Example

        inet:fqdn=vertex.link | delnode
    '''
    name = 'delnode'

    def getArgParser(self):
        pars = Cmd.getArgParser(self)
        forcehelp = 'Force delete even if it causes broken references (requires admin).'
        pars.add_argument('--force', default=False, action='store_true', help=forcehelp)
        return pars

    def runStormCmd(self, snap, genr):

        # a bit odd, but we need to be detected as a generator
        yield from ()

        if self.opts.force:
            if snap.user is not None and not snap.user.admin:
                mesg = '--force requires admin privs.'
                return self._onAuthDeny(mesg)

        for node, path in genr:
            node.delete(force=self.opts.force)

class SudoCmd(Cmd):
    '''
    Use admin priviliges to bypass standard query permissions.

    Example:

        sudo | [ inet:fqdn=vertex.link ]
    '''
    name = 'sudo'

    def runStormCmd(self, snap, genr):
        snap.elevated = True
        yield from genr

class ReIndexCmd(Cmd):
    '''
    Use admin priviliges to re index/normalize node properties.

    Example:

        foo:bar | reindex --subs

        reindex --type inet:ipv4

    NOTE: This is mostly for model updates and migrations.
          Use with caution and be very sure of what you are doing.
    '''
    name = 'reindex'

    def getArgParser(self):
        pars = Cmd.getArgParser(self)
        pars.add_argument('--type', default=None, help='Re-index all properties of a specified type.')
        pars.add_argument('--subs', default=False, action='store_true', help='Re-parse and set sub props.')
        return pars

    def runStormCmd(self, snap, genr):

        if snap.user is not None and not snap.user.admin:
            snap.warn('reindex requires an admin')
            return

        snap.elevated = True
        snap.writeable()

        # are we re-indexing a type?
        if self.opts.type is not None:

            # is the type also a form?
            form = snap.model.forms.get(self.opts.type)

            if form is not None:

                snap.printf(f'reindex form: {form.name}')
                for buid, norm in snap.xact.iterFormRows(form.name):
                    snap.stor(form.getSetOps(buid, norm))

            for prop in snap.model.getPropsByType(self.opts.type):

                snap.printf(f'reindex prop: {prop.full}')

                formname = prop.form.name

                for buid, norm in snap.xact.iterPropRows(formname, prop.name):
                    snap.stor(prop.getSetOps(buid, norm))

            return

        for node, path in genr:

            form, valu = node.ndef
            norm, info = node.form.type.norm(valu)

            subs = info.get('subs')
            if subs is not None:
                for subn, subv in subs.items():
                    if node.form.props.get(subn):
                        node.set(subn, subv)

            yield node, path

class MoveTagCmd(Cmd):
    '''
    Rename an entire tag tree and preserve time intervals.

    Example:

        movetag #foo.bar #baz.faz.bar
    '''
    name = 'movetag'

    def getArgParser(self):
        pars = Cmd.getArgParser(self)
        pars.add_argument('oldtag', help='The tag tree to rename.')
        pars.add_argument('newtag', help='The new tag tree name.')
        return pars

    def runStormCmd(self, snap, genr):

        oldt = snap.addNode('syn:tag', self.opts.oldtag)
        oldstr = oldt.ndef[1]
        oldsize = len(oldstr)

        newt = snap.addNode('syn:tag', self.opts.newtag)
        newstr = newt.ndef[1]

        retag = {oldstr: newstr}

        # first we set all the syn:tag:isnow props
        for node in snap.getNodesBy('syn:tag', self.opts.oldtag, cmpr='^='):

            tagstr = node.ndef[1]
            if tagstr == oldstr: # special case for exact match
                node.set('isnow', newstr)
                continue

            newtag = newstr + tagstr[oldsize:]

            retag[tagstr] = newtag
            node.set('isnow', newtag)

        # now we re-tag all the nodes...
        count = 0
        for node in snap.getNodesBy(f'#{oldstr}'):

            count += 1

            tags = list(node.tags.items())
            tags.sort(reverse=True)

            for name, valu in tags:

                newt = retag.get(name)
                if newt is None:
                    continue

                node.delTag(name)
                node.addTag(newt, valu=valu)

        snap.printf(f'moved tags on {count} nodes.')

        for node, path in genr:
            yield node, path

class SpinCmd(Cmd):
    '''
    Iterate through all query results, but do not yield any.
    This can be used to operate on many nodes without returning any.

    Example:

        foo:bar:size=20 [ +#hehe ] | spin

    '''
    name = 'spin'

    def runStormCmd(self, snap, genr):

        yield from ()

        for node, path in genr:
            pass

class CountCmd(Cmd):
    '''
    Iterate through query results, and print the resulting number of nodes
    which were lifted. This does yield the nodes counted.

    Example:

        foo:bar:size=20 | count

    '''
    name = 'count'

    def runStormCmd(self, snap, genr):

        i = 0
        for i, (node, path) in enumerate(genr, 1):
            yield node, path

        snap.printf(f'Counted {i} nodes.')
