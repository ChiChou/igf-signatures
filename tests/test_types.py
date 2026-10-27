from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'generator'))
from clang import Clang
from build import described

class Types(unittest.TestCase):
    def test_clang(self):
        clang=Clang()
        with tempfile.TemporaryDirectory() as temp:
            file=Path(temp)/'types.c'
            file.write_text('typedef __SIZE_TYPE__ size_t; struct Pair { int x; int y; }; extern const char *example(const char *text, void *data, unsigned int count, size_t length, double ratio, _Bool enabled, struct Pair value); extern int variadic(const char *format, ...);')
            for target,width in [('aarch64-linux-android',8),('i686-linux-android',4)]:
                rows,errors=clang.parse(file,['-x','c','-target',target])
                self.assertEqual(errors,[])
                row=next(r for r in rows if r['name']=='example')
                self.assertEqual(row['returns']['frida'],'pointer')
                self.assertEqual(row['returns']['c'],'const char *')
                self.assertEqual(row['returns']['display'],'utf8')
                args=[a['type'] for a in row['args']]
                self.assertEqual([a['frida'] for a in args],['pointer','pointer','uint','size_t','double','bool','pointer'])
                self.assertEqual(args[0]['display'],'utf8')
                self.assertEqual(args[1]['display'],'address')
                self.assertEqual(args[3]['size'],width)
                self.assertTrue(args[-1]['approximate'])
                self.assertTrue(next(r for r in rows if r['name']=='variadic')['variadic'])

    def test_abi_fallback(self):
        self.assertEqual(described('const char *')['display'],'utf8')
        self.assertEqual(described('char **')['display'],'address')
        self.assertEqual(described('unsigned long long')['frida'],'uint64')
        self.assertTrue(described('UnknownRecord')['approximate'])

if __name__=='__main__':unittest.main()
