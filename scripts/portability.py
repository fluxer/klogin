#!/usr/bin/python

import os, re

cwd = os.path.dirname(__file__)
callregex = re.compile('(?:\s|\()::(\w+)\(')
includeregex = re.compile('#include \<(.*)\>')
typeregex = re.compile('(?:\s|^)(\w+_t)\s\w+')
lcallmatches = []
lincludematches = []
typematches = []

for root, subdirs, files in os.walk('%s/../src' % cwd):
    for sfile in files:
        if sfile.endswith(('.cpp', '.hpp', 'h')):
            sfull = '%s/%s' % (root, sfile)
            with open(sfull, 'rb') as f:
                scontent = f.read()
            scontent = scontent.decode('utf-8')
            for smatch in callregex.findall(scontent):
                if smatch and not smatch in lcallmatches:
                    lcallmatches.append(smatch)
            for smatch in includeregex.findall(scontent):
                if smatch and not smatch in lincludematches:
                    if smatch.startswith('Q'):
                        continue
                    lincludematches.append(smatch)
            for smatch in typeregex.findall(scontent):
                if smatch and not smatch in typematches:
                    typematches.append(smatch)

print('Function calls:')
for toprint in sorted(lcallmatches):
    print('    %s' % toprint)
print('')
print('System includes:')
for toprint in sorted(lincludematches):
    print('    %s' % toprint)
print('')
print('System types:')
for toprint in sorted(typematches):
    print('    %s' % toprint)
print('')
