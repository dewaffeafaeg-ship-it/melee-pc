#!/usr/bin/env python3
"""Diagnostics for a wasm that Binaryen fails to parse.
usage: diag_wasm.py file.wasm [byte_offset]
Prints sections, target_features, and (given an offset) the function that contains it."""
import sys

p = sys.argv[1]
target = int(sys.argv[2]) if len(sys.argv) > 2 else None
b = open(p, 'rb').read()


def leb(i):
    r = s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7f) << s; s += 7
        if not x & 0x80:
            return r, i


print('file', p, 'size', len(b))
i = 8; secs = []
while i < len(b):
    sid = b[i]; i += 1
    sz, j = leb(i)
    name = None
    if sid == 0:
        nl, k = leb(j); name = b[k:k + nl].decode('utf8', 'replace')
    secs.append((sid, name, j, sz))
    print(f'  section id={sid:2d} name={name} start={j} size={sz} end={j + sz}')
    i = j + sz

for sid, name, start, sz in secs:
    if sid == 0 and name == 'target_features':
        nl, k = leb(start); k += nl
        n, k = leb(k); out = []
        for _ in range(n):
            pref = chr(b[k]); k += 1
            l, k = leb(k); out.append(pref + b[k:k + l].decode()); k += l
        print('target_features:', ' '.join(out))

# imported function count + function names, to name the function at the offset
nimp = 0
for sid, name, start, sz in secs:
    if sid == 2:
        n, k = leb(start)
        for _ in range(n):
            l, k = leb(k); k += l
            l, k = leb(k); k += l
            kind = b[k]; k += 1
            if kind == 0:
                nimp += 1; _, k = leb(k)
            elif kind == 1:
                k += 1; fl, k = leb(k); _, k = leb(k)
                if fl & 1: _, k = leb(k)
            elif kind == 2:
                fl, k = leb(k); _, k = leb(k)
                if fl & 1: _, k = leb(k)
            elif kind == 3:
                k += 2
            else:
                _, k = leb(k); _, k = leb(k)
print('imported functions:', nimp)
names = {}
for sid, name, start, sz in secs:
    if sid == 0 and name == 'name':
        nl, k = leb(start); k += nl
        end = start + sz
        while k < end:
            sub = b[k]; k += 1
            ssz, k2 = leb(k)
            if sub == 1:
                n, q = leb(k2)
                for _ in range(n):
                    idx, q = leb(q); l, q = leb(q)
                    names[idx] = b[q:q + l].decode('utf8', 'replace'); q += l
            k = k2 + ssz

if target is not None:
    found = False
    for sid, name, start, sz in secs:
        if sid == 10 and start <= target < start + sz:
            n, k = leb(start)
            for fi in range(n):
                fs, k2 = leb(k)
                if k2 <= target < k2 + fs:
                    found = True
                    fn = names.get(nimp + fi, '?')
                    print(f'offset {target} is in function #{nimp + fi} "{fn}" (body {k2}..{k2 + fs}, {fs} bytes)')
                    lo = max(k2, target - 40); hi = min(k2 + fs, target + 40)
                    print('bytes before :', b[lo:target].hex())
                    print('byte at off  :', b[target:target + 1].hex())
                    print('bytes after  :', b[target + 1:hi].hex())
                    break
                k = k2 + fs
    if not found:
        print(f'offset {target} is not inside the code section')
