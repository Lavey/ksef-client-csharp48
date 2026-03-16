#!/usr/bin/env python3
import os
import re

def fix_file_scoped_namespace(content):
    """Convert file-scoped namespace to block-scoped namespace"""
    
    # Pattern: namespace Foo.Bar;
    # We need to match the namespace statement and wrap the rest in braces
    match = re.search(r'^namespace\s+([\w\.]+);$', content, re.MULTILINE)
    if not match:
        return content
    
    namespace_name = match.group(1)
    namespace_line = match.group(0)
    
    # Find the position of the namespace statement
    namespace_pos = content.find(namespace_line)
    
    # Split content
    before_namespace = content[:namespace_pos]
    after_namespace = content[namespace_pos + len(namespace_line):].lstrip('\n')
    
    # Build new content with block-scoped namespace
    new_content = before_namespace + f'namespace {namespace_name}\n{{\n'
    new_content += after_namespace
    new_content += '\n}\n'
    
    return new_content

repo = '/home/runner/work/ksef-client-csharp48/ksef-client-csharp48'
count = 0

for root, dirs, files in os.walk(repo):
    dirs[:] = [d for d in dirs if d != '.git' and d != 'obj' and d != 'bin']
    for fname in files:
        if fname.endswith('.cs'):
            path = os.path.join(root, fname)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            new_content = fix_file_scoped_namespace(content)
            if new_content != content:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f'Fixed file-scoped namespace: {path}')
                count += 1

print(f'\nTotal files fixed: {count}')
