#!/usr/bin/env python3
import os
import re

def fix_conditional_compilation_files(content, filepath):
    """Fix files that have #if directives wrapping the namespace"""
    
    # Check if file has #if NETSTANDARD2_0 at the beginning
    if not content.strip().startswith('#if NETSTANDARD2_0'):
        return content
    
    # Remove the #if NETSTANDARD2_0 and #endif wrappers
    lines = content.split('\n')
    result_lines = []
    
    for i, line in enumerate(lines):
        # Skip #if NETSTANDARD2_0
        if line.strip() == '#if NETSTANDARD2_0':
            continue
        # Skip #endif (but not in the middle of code, only standalone)
        if line.strip() == '#endif':
            continue
        # Skip trailing empty braces
        if line.strip() == '}' and i > 0 and lines[i-1].strip() == '#endif':
            continue
        result_lines.append(line)
    
    return '\n'.join(result_lines)

repo = '/home/runner/work/ksef-client-csharp48/ksef-client-csharp48'
count = 0

for root, dirs, files in os.walk(repo):
    dirs[:] = [d for d in dirs if d != '.git' and d != 'obj' and d != 'bin']
    for fname in files:
        if fname.endswith('.cs'):
            path = os.path.join(root, fname)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            new_content = fix_conditional_compilation_files(content, path)
            if new_content != content:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f'Fixed conditional compilation: {path}')
                count += 1

print(f'\nTotal files fixed: {count}')
