import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import urllib.request

from clang import Clang

ROOT = Path(__file__).resolve().parent.parent
CONFIG = json.loads((ROOT / 'sources.json').read_text())
ARCHES = {'arm': ('arm-linux-androideabi', 'armv7a-linux-androideabi'), 'arm64': ('aarch64-linux-android', 'aarch64-linux-android'), 'ia32': ('i686-linux-android', 'i686-linux-android'), 'x64': ('x86_64-linux-android', 'x86_64-linux-android')}


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


class Store:
    def __init__(self, path, version):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.unlink(missing_ok=True)
        self.db = sqlite3.connect(path)
        self.db.executescript((ROOT / 'schema.sql').read_text())
        self.db.executemany('INSERT INTO metadata VALUES (?, ?)', [('version', version), ('schema', '1')])
        self.types = {}

    def source(self, platform, sdk, version, revision, url, compiler):
        return self.db.execute('INSERT INTO sources(platform,sdk,version,revision,url,compiler) VALUES(?,?,?,?,?,?)', (platform,sdk,version,revision,url,compiler)).lastrowid

    def typ(self, t):
        key = (t['c'], t['canonical'], compact(t['frida']), t['size'], t['display'], int(t['approximate']))
        if key not in self.types:
            self.types[key] = self.db.execute('INSERT INTO types(c_spelling,canonical_c,frida_type,size,display_hint,approximate) VALUES(?,?,?,?,?,?)', key).lastrowid
        return self.types[key]

    def function(self, source, platform, arch, module, row, kind='function'):
        result = self.db.execute('INSERT OR IGNORE INTO functions(source_id,platform,arch,module,symbol,name,return_type_id,variadic,header,kind) VALUES(?,?,?,?,?,?,?,?,?,?)', (source,platform,arch,module,row['symbol'],row['name'],self.typ(row['returns']),int(row['variadic']),row['header'],kind))
        if result.rowcount:
            ident = result.lastrowid
            for i, arg in enumerate(row['args']):
                self.db.execute('INSERT INTO parameters VALUES(?,?,?,?)', (ident,i,arg['name'],self.typ(arg['type'])))
            return ident
        return self.db.execute('SELECT id FROM functions WHERE source_id=? AND platform=? AND arch=? AND module=? AND symbol=? AND kind=?', (source,platform,arch,module,row['symbol'],kind)).fetchone()[0]


def fetch(project, revision, path, cache):
    key = hashlib.sha256(f'{project}/{revision}/{path}'.encode()).hexdigest()
    file = cache / key
    if not file.exists():
        url = f'https://android.googlesource.com/{project}/+/{revision}/{path}?format=TEXT'
        data = base64.b64decode(urllib.request.urlopen(url, timeout=60).read())
        file.write_bytes(data)
    return file.read_bytes()


def android(clang, store, ndk, diagnostics):
    tool = ndk / 'toolchains/llvm/prebuilt/darwin-x86_64'
    if not tool.exists():
        tool = ndk / 'toolchains/llvm/prebuilt/linux-x86_64'
    root = tool / 'sysroot'
    inc = root / 'usr/include'
    groups = ['android','aaudio','amidi','camera','media','EGL','GLES','GLES2','GLES3','SLES','OMXAL','unicode','sys','arpa','net','netinet','netpacket']
    headers = sorted(list(inc.glob('*.h')) + [h for g in groups for h in (inc/g).rglob('*.h')] + [inc/'vulkan/vulkan.h'])
    headers = [h for h in headers if not h.name.endswith(('_utils.h','_auto_utils.h','_interface_utils.h')) and str(h.relative_to(inc)) not in ('EGL/Platform.h','sys/ucontext.h','time64.h')]
    revision = re.search(r'Pkg.Revision\s*=\s*(\S+)', (ndk/'source.properties').read_text())[1]
    source = store.source('android','NDK',revision,revision,'https://developer.android.com/ndk',clang.version)
    for arch, (triple, target) in ARCHES.items():
        exports = {}
        for lib in sorted((root/'usr/lib'/triple/str(CONFIG['api'])).glob('*.so')):
            if lib.read_bytes()[:4] != b'\x7fELF': continue
            output = subprocess.check_output([str(tool/'bin/llvm-nm'),'-D','--defined-only','--format=posix',str(lib)], text=True)
            for line in output.splitlines():
                cols = line.split()
                if len(cols)>1 and cols[1].upper() in ('T','W','I'):
                    exports.setdefault(cols[0].split('@')[0], []).append(lib.name)
        args = ['-x','c','-target',target+str(CONFIG['api']),'--sysroot='+str(root),'-isystem',str(inc/triple),'-D_GNU_SOURCE','-D_LARGEFILE64_SOURCE','-DGL_GLEXT_PROTOTYPES','-DEGL_EGLEXT_PROTOTYPES','-DVK_USE_PLATFORM_ANDROID_KHR','-Wno-everything']
        for h in headers:
            extra = {'EGL':['-include','EGL/egl.h'], 'GLES':['-include','GLES/gl.h'], 'GLES2':['-include','GLES2/gl2.h']}.get(h.parent.name, [])
            rows, errors = clang.parse(h, args+extra)
            if errors:
                diagnostics.append({'platform':'android','arch':arch,'header':str(h.relative_to(inc)),'errors':errors[:8]})
                continue
            for row in rows:
                if row['symbol'] not in exports: continue
                row['header'] = str(Path(row['header']).relative_to(inc)) if row['header'].startswith(str(inc)) else Path(row['header']).name
                for lib in exports[row['symbol']]: store.function(source,'android',arch,lib,row)
        store.db.commit()
        print('Android', arch, 'complete', flush=True)
    return tool


def apple(clang, store, cache, diagnostics):
    for sdkname, arch, target in [('iphoneos','arm64','arm64-apple-ios17.0'),('iphonesimulator','x64','x86_64-apple-ios17.0-simulator'),('macosx','arm64','arm64-apple-macos14.0'),('macosx','x64','x86_64-apple-macos14.0')]:
        sdk = Path(subprocess.check_output(['xcrun','--sdk',sdkname,'--show-sdk-path'],text=True).strip())
        settings = json.loads((sdk/'SDKSettings.json').read_text())
        source = store.source('darwin',sdkname,settings['Version'],settings.get('ProductBuildVersion',settings.get('CanonicalName',sdk.name)),'https://developer.apple.com/xcode/',clang.version)
        inc = sdk/'usr/include'
        args = ['-x','objective-c','-target',target,'-isysroot',str(sdk),'-fblocks','-fno-modules','-D_DARWIN_C_SOURCE','-Wno-everything']
        groups = ['CommonCrypto','dispatch','os','objc','xpc','mach','sys','arpa','netinet']
        headers = sorted(list(inc.glob('*.h')) + [h for g in groups for h in (inc/g).glob('*.h')])
        for fw in CONFIG['frameworks']:
            h = sdk/f'System/Library/Frameworks/{fw}.framework/Headers/{fw}.h'
            if h.exists(): headers.append(h)
        for h in headers:
            extra = []
            if h.parent.name == 'dispatch': extra = ['-include','dispatch/dispatch.h']
            if h.parent.name == 'xpc': extra = ['-include','xpc/xpc.h']
            rows, errors = clang.parse(h,args+extra)
            if errors: diagnostics.append({'platform':sdkname,'arch':arch,'header':str(h.relative_to(sdk)),'errors':errors[:8]})
            # Valid declarations can precede an unavailable SDK submodule; reject invalid types below.
            for row in rows:
                if not row['header'].startswith(str(sdk)): continue
                row['header'] = str(Path(row['header']).relative_to(sdk))
                if row['returns']['canonical'] == '' or any(not a['type']['canonical'] for a in row['args']): continue
                row['symbol'] = row['symbol'].removeprefix('_')
                fw = re.search(r'/([^/]+)\.framework/', row['header'])
                module = fw[1] if fw else 'libSystem'
                for directory,lib in [('CommonCrypto','libcommonCrypto'),('dispatch','libdispatch'),('objc','libobjc'),('xpc','libxpc')]:
                    if f'/include/{directory}/' in row['header']: module=lib
                for prefix,lib in [('sqlite3','libsqlite3'),('zlib','libz'),('compression','libcompression'),('dns_sd','libdns_sd')]:
                    if Path(row['header']).name.startswith(prefix): module=lib
                store.function(source,'darwin',arch,module,row)
        store.db.commit()
        print(sdkname, arch, 'complete',flush=True)


def described(raw, size=None, canonical=None):
    """Conservative fallback for source-based ABI dumps and kernel declarations."""
    c = canonical or raw
    bare = re.sub(r'\b(const|volatile|restrict|__user|__force)\b','',c).strip()
    hint, approximate = 'integer', False
    if '*' in bare or '&' in bare or '[' in bare:
        frida,hint = 'pointer', 'utf8' if re.fullmatch(r'char\s*\*',bare) else 'address'
    elif bare == 'void': frida,hint='void','none'
    elif bare in ('float','double'): frida,hint=bare,'float'
    elif bare in ('bool','_Bool'): frida='bool'
    elif bare in ('size_t','ssize_t'): frida=bare
    elif bare in ('int','unsigned int','long','unsigned long'): frida={'unsigned int':'uint','unsigned long':'ulong'}.get(bare,bare)
    elif bare in ('char','signed char','unsigned char','short','short int','unsigned short','unsigned short int','long long','long long int','unsigned long long','unsigned long long int'):
        bits = 8 if 'char' in bare else 16 if 'short' in bare else 64
        frida=('uint' if 'unsigned' in bare else 'int')+str(bits)
    elif re.fullmatch(r'u?int(?:8|16|32|64)_t',bare): frida=bare[:-2]
    elif size in (1,2,4,8): frida=('uint' if 'unsigned' in bare else 'int')+str(size*8);approximate=True
    else: frida,hint,approximate='pointer','address',True
    return {'c':raw,'canonical':c,'frida':frida,'size':size,'display':hint,'approximate':approximate}


def platform(store, cache):
    cfg=CONFIG['vndk']
    source=store.source('android','AOSP platform',str(cfg['api']),cfg['revision'],'https://android.googlesource.com/platform/prebuilts/abi-dumps/vndk/','AOSP header-abi-dumper')
    for arch,directory in [('arm','arm'),('arm64','arm64'),('ia32','x86'),('x64','x86_64')]:
        for lib in CONFIG['libraries']:
            path=f"{cfg['api']}/64/{directory}/source-based/{lib}.so.lsdump"
            raw=fetch('platform/prebuilts/abi-dumps/vndk',cfg['revision'],path,cache)
            if not raw.lstrip().startswith(b'{'):
                raw=fetch('platform/prebuilts/abi-dumps/platform',CONFIG['platform'],path,cache)
            dump=json.loads(raw)
            exports={r['name'] for r in dump.get('elf_functions',[])}
            types={t['linker_set_key']:t for key,values in dump.items() if key.endswith('_types') for t in values}
            def typ(key):
                t=types.get(key,{})
                return described(t.get('name',key),t.get('size'))
            for f in dump.get('functions',[]):
                if f['linker_set_key'] not in exports: continue
                row={'symbol':f['linker_set_key'],'name':f.get('function_name',f['linker_set_key']),'header':f.get('source_file',''),'returns':typ(f['return_type']),'args':[{'name':'','type':typ(a['referenced_type'])} for a in f.get('parameters',[])],'variadic':f.get('is_variadic',False)}
                store.function(source,'android',arch,lib+'.so',row)
        store.db.commit()
        print('AOSP platform',arch,'complete',flush=True)


def sqlite(clang, store, tool, cache):
    revision=CONFIG['sqlite']
    file=cache/'sqlite3.h'
    file.write_bytes(fetch('platform/external/sqlite',revision,'dist/sqlite-autoconf-3440400/sqlite3.h',cache))
    source=store.source('android','SQLite','3.44.4',revision,'https://android.googlesource.com/platform/external/sqlite/',clang.version)
    for arch,(_,target) in ARCHES.items():
        rows,errors=clang.parse(file,['-x','c','-target',target+str(CONFIG['api']),'--sysroot='+str(tool/'sysroot')])
        if errors: raise RuntimeError(errors)
        for row in rows:
            if not row['symbol'].startswith('sqlite3_'):continue
            row['header']='sqlite3.h'
            store.function(source,'android',arch,'libsqlite.so',row)
    store.db.commit()


def syscalls(store, tool, cache):
    revision=CONFIG['kernel']
    source=store.source('android','Linux kernel','android15-6.6',revision,'https://android.googlesource.com/kernel/common/','source declarations')
    text=fetch('kernel/common',revision,'include/linux/syscalls.h',cache).decode()
    text=re.sub(r'/\*.*?\*/','',text,flags=re.S)
    prototypes={name:re.sub(r'\s+',' ',args).strip() for name,args in re.findall(r'asmlinkage\s+long\s+sys_(\w+)\s*\((.*?)\)\s*;',text,re.S)}
    tables={}
    for arch,path in [('arm','arch/arm/tools/syscall.tbl'),('ia32','arch/x86/entry/syscalls/syscall_32.tbl'),('x64','arch/x86/entry/syscalls/syscall_64.tbl')]:
        rows=[]
        for line in fetch('kernel/common',revision,path,cache).decode().splitlines():
            cols=line.split()
            if not cols or not cols[0].isdigit() or cols[1] in ('oabi','x32'):continue
            rows.append((int(cols[0]),cols[2],cols[3].removeprefix('sys_') if len(cols)>3 else cols[2]))
        tables[arch]=rows
    output=subprocess.check_output([str(tool/'bin/clang'),'--target=aarch64-linux-android35','--sysroot='+str(tool/'sysroot'),'-dM','-E','-include','asm/unistd.h','-x','c','/dev/null'],text=True)
    macros=dict(re.findall(r'^#define (__NR(?:3264)?_\w+) (.+)$',output,re.M))
    rows=[]
    for key,value in macros.items():
        if not key.startswith('__NR_') or key=='__NR_syscalls':continue
        for _ in range(8):
            if value.isdigit():break
            value=macros.get(value,'')
        if value.isdigit():rows.append((int(value),key[5:],key[5:]))
    tables['arm64']=rows
    for arch,rows in tables.items():
        for number,name,entry in rows:
            args=prototypes.get(entry,prototypes.get(name));ident=None
            if args is not None:
                params=[]
                if args and args!='void':
                    for arg in args.split(','):
                        match=re.match(r'(.+?[\s*])([A-Za-z_]\w*)(\[.*\])?$',arg.strip())
                        raw,pname=(match[1].strip()+(match[3] or ''),match[2]) if match else (arg.strip(),'')
                        params.append({'name':pname,'type':described(raw)})
                ident=store.function(source,'android',arch,'kernel',{'symbol':name,'name':name,'header':'include/linux/syscalls.h','returns':described('long',8 if arch in ('arm64','x64') else 4),'args':params,'variadic':False},'syscall')
            store.db.execute('INSERT OR IGNORE INTO syscalls VALUES(?,?,?,?,?)',(source,arch,number,name,ident))
    store.db.commit()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--ndk',type=Path,default=Path(os.environ.get('ANDROID_NDK_HOME',Path.home()/'Library/Android/sdk/ndk'/CONFIG['ndk'])))
    parser.add_argument('--version',required=True)
    parser.add_argument('--output',type=Path,default=ROOT/'dist')
    parser.add_argument('--cache',type=Path,default=ROOT/'.cache')
    parser.add_argument('--only',choices=['android','apple'])
    args=parser.parse_args()
    args.cache.mkdir(parents=True,exist_ok=True)
    clang=Clang();store=Store(args.output/'signatures.db',args.version);diagnostics=[]
    if args.only!='apple':
        tool=android(clang,store,args.ndk,diagnostics)
        platform(store,args.cache)
        sqlite(clang,store,tool,args.cache)
        syscalls(store,tool,args.cache)
    if args.only!='android':apple(clang,store,args.cache,diagnostics)
    store.db.commit()
    assert store.db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
    assert not store.db.execute('PRAGMA foreign_key_check').fetchall()
    counts=dict(store.db.execute('SELECT platform,COUNT(*) FROM functions GROUP BY platform'))
    store.db.execute('VACUUM');store.db.close()
    blob=(args.output/'signatures.db').read_bytes()
    packed=gzip.compress(blob,mtime=0)
    (args.output/'signatures.db.gz').write_bytes(packed)
    manifest={'schema':1,'version':args.version,'sha256':hashlib.sha256(blob).hexdigest(),'gzipSha256':hashlib.sha256(packed).hexdigest(),'bytes':len(blob),'gzipBytes':len(packed),'functions':counts}
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (args.output/'diagnostics.json').write_text(json.dumps(diagnostics,indent=2)+'\n')
    print(json.dumps(manifest,indent=2),flush=True)

if __name__=='__main__': main()
