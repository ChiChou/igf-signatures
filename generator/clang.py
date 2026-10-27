"""Small stdlib-only binding to the stable libclang C API used by the generator."""
import ctypes as C
import os
from pathlib import Path
import subprocess

class String(C.Structure):
    _fields_ = [('data', C.c_void_p), ('flags', C.c_uint)]
class Cursor(C.Structure):
    _fields_ = [('kind', C.c_uint), ('xdata', C.c_int), ('data', C.c_void_p * 3)]
class Type(C.Structure):
    _fields_ = [('kind', C.c_uint), ('data', C.c_void_p * 2)]
class Location(C.Structure):
    _fields_ = [('data', C.c_void_p * 2), ('offset', C.c_uint)]
Visitor = C.CFUNCTYPE(C.c_uint, Cursor, Cursor, C.c_void_p)

class Clang:
    def __init__(self):
        path = os.environ.get('LIBCLANG')
        if not path:
            clang = Path(subprocess.check_output(['xcrun', '--find', 'clang'], text=True).strip())
            path = str(clang.parent.parent / 'lib/libclang.dylib')
        self.lib = C.CDLL(path)
        def bind(name, result, *args):
            fn = getattr(self.lib, 'clang_' + name)
            fn.restype, fn.argtypes = result, args
            setattr(self, name, fn)
        bind('getCString', C.c_char_p, String)
        bind('disposeString', None, String)
        bind('getClangVersion', String)
        bind('createIndex', C.c_void_p, C.c_int, C.c_int)
        bind('disposeIndex', None, C.c_void_p)
        bind('parseTranslationUnit', C.c_void_p, C.c_void_p, C.c_char_p, C.POINTER(C.c_char_p), C.c_int, C.c_void_p, C.c_uint, C.c_uint)
        bind('disposeTranslationUnit', None, C.c_void_p)
        bind('getTranslationUnitCursor', Cursor, C.c_void_p)
        bind('visitChildren', C.c_uint, Cursor, Visitor, C.c_void_p)
        bind('getCursorSpelling', String, Cursor)
        bind('Cursor_getMangling', String, Cursor)
        bind('getCursorLinkage', C.c_uint, Cursor)
        bind('getCursorLocation', Location, Cursor)
        bind('getSpellingLocation', None, Location, C.POINTER(C.c_void_p), C.POINTER(C.c_uint), C.POINTER(C.c_uint), C.POINTER(C.c_uint))
        bind('getFileName', String, C.c_void_p)
        bind('getCursorType', Type, Cursor)
        bind('getCanonicalType', Type, Type)
        bind('getTypeSpelling', String, Type)
        bind('getPointeeType', Type, Type)
        bind('getTypeDeclaration', Cursor, Type)
        bind('getEnumDeclIntegerType', Type, Cursor)
        bind('Type_getSizeOf', C.c_longlong, Type)
        bind('getCursorResultType', Type, Cursor)
        bind('Cursor_getNumArguments', C.c_int, Cursor)
        bind('Cursor_getArgument', Cursor, Cursor, C.c_uint)
        bind('isFunctionTypeVariadic', C.c_uint, Type)
        bind('getNumDiagnostics', C.c_uint, C.c_void_p)
        bind('getDiagnostic', C.c_void_p, C.c_void_p, C.c_uint)
        bind('getDiagnosticSeverity', C.c_uint, C.c_void_p)
        bind('getDiagnosticSpelling', String, C.c_void_p)
        bind('disposeDiagnostic', None, C.c_void_p)
        self.index = self.createIndex(1, 0)
        self.version = self.text(self.getClangVersion())

    def text(self, value):
        result = (self.getCString(value) or b'').decode('utf8', errors='replace')
        self.disposeString(value)
        return result

    def spelling(self, typ):
        return self.text(self.getTypeSpelling(typ))

    def convert(self, typ):
        raw = self.spelling(typ)
        canonical = self.getCanonicalType(typ)
        k = canonical.kind
        size = self.Type_getSizeOf(canonical)
        hint, approximate = 'integer', False
        if raw in ('size_t', 'ssize_t'):
            frida = raw
        elif k == 2:
            frida, hint = 'void', 'none'
        elif k == 3:
            frida = 'bool'
        elif k in (27, 28, 109):
            frida, hint = 'pointer', 'objc'
        elif k == 21:
            frida, hint = 'float', 'float'
        elif k == 22:
            frida, hint = 'double', 'float'
        elif k == 106:
            underlying = self.convert(self.getEnumDeclIntegerType(self.getTypeDeclaration(canonical)))
            frida = underlying['frida']
        elif k in (101, 102, 103, 104, 112, 114, 115, 116):
            frida, hint = 'pointer', 'address'
            if k == 101:
                pointee = self.getCanonicalType(self.getPointeeType(canonical))
                if pointee.kind in (4, 13): hint = 'utf8'
        elif k in (4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 19):
            frida = {9: 'uint', 10: 'ulong', 17: 'int', 18: 'long'}.get(k)
            if frida is None:
                frida = ('uint' if k <= 11 else 'int') + str(size * 8)
                if size not in (1, 2, 4, 8): frida, approximate = 'pointer', True
        else:
            frida, hint, approximate = 'pointer', 'address', True
        return {'c': raw, 'canonical': self.spelling(canonical), 'frida': frida,
                'size': size if size >= 0 else None, 'display': hint, 'approximate': approximate}

    def parse(self, file, args):
        argv = (C.c_char_p * len(args))(*(x.encode() for x in args))
        unit = self.parseTranslationUnit(self.index, str(file).encode(), argv, len(args), None, 0, 0x40)
        if not unit: return [], ['libclang could not parse translation unit']
        errors, rows = [], []
        for i in range(self.getNumDiagnostics(unit)):
            d = self.getDiagnostic(unit, i)
            if self.getDiagnosticSeverity(d) >= 3: errors.append(self.text(self.getDiagnosticSpelling(d)))
            self.disposeDiagnostic(d)
        @Visitor
        def visit(cursor, parent, data):
            if cursor.kind == 8 and self.getCursorLinkage(cursor) == 4:
                file = C.c_void_p()
                self.getSpellingLocation(self.getCursorLocation(cursor), C.byref(file), None, None, None)
                if not file: return 1
                header = self.text(self.getFileName(file))
                name = self.text(self.getCursorSpelling(cursor))
                symbol = self.text(self.Cursor_getMangling(cursor)) or name
                args = []
                for i in range(max(0, self.Cursor_getNumArguments(cursor))):
                    arg = self.Cursor_getArgument(cursor, i)
                    args.append({'name': self.text(self.getCursorSpelling(arg)), 'type': self.convert(self.getCursorType(arg))})
                rows.append({'symbol': symbol, 'name': name, 'header': header, 'args': args, 'returns': self.convert(self.getCursorResultType(cursor)), 'variadic': bool(self.isFunctionTypeVariadic(self.getCursorType(cursor)))})
                return 1
            return 2 if cursor.kind in (22, 23, 300) else 1
        self.visitChildren(self.getTranslationUnitCursor(unit), visit, None)
        self.disposeTranslationUnit(unit)
        return rows, errors
