import json
import sqlite3
import sys
from pathlib import Path

path=Path(sys.argv[1])
db=sqlite3.connect(f'file:{path.resolve()}?mode=ro',uri=True)
assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
assert not db.execute('PRAGMA foreign_key_check').fetchall()
assert db.execute('PRAGMA user_version').fetchone()[0]==1
for platform,names in [('android',['puts','malloc','SSL_read','sqlite3_open','AAssetManager_open']),('darwin',['puts','malloc','CCCrypt','SecItemCopyMatching','dispatch_async'])]:
    for name in names:
        assert db.execute('SELECT 1 FROM functions WHERE platform=? AND symbol=?',(platform,name)).fetchone(),(platform,name)
    arg=db.execute('SELECT t.* FROM types t JOIN parameters p ON p.type_id=t.id JOIN functions f ON p.function_id=f.id WHERE f.platform=? AND f.symbol=? AND p.position=0 LIMIT 1',(platform,'puts')).fetchone()
    assert arg[1]=='const char *' and json.loads(arg[3])=='pointer' and arg[5]=='utf8',(platform,arg)
assert db.execute("SELECT COUNT(*) FROM syscalls").fetchone()[0]>1000
assert db.execute("SELECT COUNT(*) FROM functions WHERE platform='android'").fetchone()[0]>15000
assert db.execute("SELECT COUNT(*) FROM functions WHERE platform='darwin'").fetchone()[0]>10000
allowed={'void','pointer','int','uint','long','ulong','char','uchar','size_t','ssize_t','float','double','int8','uint8','int16','uint16','int32','uint32','int64','uint64','bool'}
for value, in db.execute('SELECT frida_type FROM types'):
    assert json.loads(value) in allowed,value
print('Validated SQLite integrity, foreign keys, platform coverage, syscall tables, Frida types and string hints.')
