#!/usr/bin/env python3
import os
import re

def add_missing_usings(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if file already has using statements
    has_usings = 'using System;' in content or 'using System.' in content
    
    # Determine which usings are needed
    needed_usings = set()
    
    if 'Task' in content or 'Task<' in content:
        needed_usings.add('using System.Threading.Tasks;')
    if 'CancellationToken' in content:
        needed_usings.add('using System.Threading;')
    if 'IEnumerable' in content or 'IList' in content or 'List<' in content or 'Dictionary<' in content or 'ICollection' in content:
        needed_usings.add('using System.Collections.Generic;')
    if 'HttpMethod' in content or 'HttpClient' in content or 'HttpContent' in content or 'HttpResponseMessage' in content:
        needed_usings.add('using System.Net.Http;')
    if 'X509Certificate2' in content:
        needed_usings.add('using System.Security.Cryptography.X509Certificates;')
    if any(x in content for x in ['SHA256', 'RSA', 'ECDsa', 'AesGcm', 'HashAlgorithm', 'AsymmetricAlgorithm']):
        needed_usings.add('using System.Security.Cryptography;')
    if 'StringBuilder' in content or 'Encoding' in content:
        needed_usings.add('using System.Text;')
    if 'Stream' in content or 'MemoryStream' in content or 'File' in content:
        needed_usings.add('using System.IO;')
    if 'IntPtr' in content or 'DateTimeOffset' in content or 'DateTime' in content or 'TimeSpan' in content or 'Guid' in content or 'ArgumentNullException' in content or 'Exception' in content or 'IDisposable' in content or 'Func<' in content or 'Action<' in content:
        needed_usings.add('using System;')
    if 'Linq' in content or '.Select(' in content or '.Where(' in content or '.FirstOrDefault(' in content or '.Any(' in content:
        needed_usings.add('using System.Linq;')
    
    if not needed_usings:
        return False
    
    # Find existing usings
    existing_usings = set()
    for line in content.split('\n'):
        if line.strip().startswith('using ') and line.strip().endswith(';'):
            existing_usings.add(line.strip())
    
    # Add only missing usings
    new_usings = needed_usings - existing_usings
    if not new_usings:
        return False
    
    # Find where to insert (after initial comments/blank lines, before namespace)
    lines = content.split('\n')
    insert_pos = 0
    for i, line in enumerate(lines):
        if line.strip().startswith('namespace '):
            insert_pos = i
            break
        if line.strip() and not line.strip().startswith('//') and not line.strip().startswith('using '):
            insert_pos = i
            break
    
    # Insert usings
    sorted_usings = sorted(list(new_usings))
    usings_block = '\n'.join(sorted_usings) + '\n'
    
    if insert_pos == 0:
        new_content = usings_block + content
    else:
        new_content = '\n'.join(lines[:insert_pos]) + '\n' + usings_block + '\n'.join(lines[insert_pos:])
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    return True

repo = '/home/runner/work/ksef-client-csharp48/ksef-client-csharp48'
count = 0
for root, dirs, files in os.walk(repo):
    dirs[:] = [d for d in dirs if d != '.git' and d != 'obj' and d != 'bin']
    for fname in files:
        if fname.endswith('.cs'):
            path = os.path.join(root, fname)
            if add_missing_usings(path):
                print(f'Added usings to: {path}')
                count += 1

print(f'\nTotal files updated: {count}')
