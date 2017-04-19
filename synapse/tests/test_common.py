from synapse.tests.common import *

class CommonTest(SynTest):

    def test_common_vertup(self):
        self.assertEqual( vertup('1.3.30'), (1,3,30) )
        self.assertTrue( vertup('30.40.50') > (9,0) )

    def test_common_genfile(self):
        with self.getTestDir() as testdir:
            fd = genfile(testdir,'woot','foo.bin')
            fd.close()

    def test_common_guid(self):
        iden0 = guid()
        iden1 = guid('foo bar baz')
        iden2 = guid('foo bar baz')
        self.ne(iden0,iden1)
        self.eq(iden1,iden2)

class CmdGenTest(SynTest):

    def test_simple_sequence(self):

        cmdg = CmdGenerator(['foo', 'bar'])
        self.eq(cmdg(), 'foo')
        self.eq(cmdg(), 'bar')
        self.eq(cmdg(), 'quit')
        self.eq(cmdg(), 'quit')

    def test_end_actions(self):
        cmdg = CmdGenerator(['foo', 'bar'], on_end='spam')
        self.eq(cmdg(), 'foo')
        self.eq(cmdg(), 'bar')
        self.eq(cmdg(), 'spam')
        self.eq(cmdg(), 'spam')

    def test_end_exception(self):
        cmdg = CmdGenerator(['foo', 'bar'], on_end=EOFError)
        self.eq(cmdg(), 'foo')
        self.eq(cmdg(), 'bar')
        with self.raises(EOFError) as cm:
            cmdg()
        self.assertIn('No further actions', str(cm.exception))

    def test_end_exception_unknown(self):
        cmdg = CmdGenerator(['foo', 'bar'], on_end=1)
        self.eq(cmdg(), 'foo')
        self.eq(cmdg(), 'bar')
        with self.raises(Exception) as cm:
            cmdg()
        self.assertIn('Unhandled end action', str(cm.exception))