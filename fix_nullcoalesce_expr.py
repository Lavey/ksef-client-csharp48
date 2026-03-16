#!/usr/bin/env python3
import os
import re

def fix_null_coalesce_in_expressions(content):
    """Fix ??= operator that appears in expression-bodied members"""
    
    # Pattern: => _var ??= something;
    # Should become: { get { if (_var == null) _var = something; return _var; } }
    
    # Find property declarations with => that contain "if ("
    pattern = r'(public\s+(?:static\s+)?[\w<>]+\s+\w+)\s*=>\s*if\s*\(([^)]+)\s*==\s*null\)\s*(\w+)\s*=\s*([^;]+);'
    
    def replace_func(match):
        declaration = match.group(1)
        condition_var = match.group(2)
        assign_var = match.group(3)
        value = match.group(4)
        
        return f'{declaration}\n    {{\n        get\n        {{\n            if ({condition_var} == null) {assign_var} = {value};\n            return {assign_var};\n        }}\n    }}'
    
    content = re.sub(pattern, replace_func, content)
    
    return content

repo = '/home/runner/work/ksef-client-csharp48/ksef-client-csharp48'
count = 0

for root, dirs, files in os.walk(repo):
    dirs[:] = [d for d in dirs if d != '.git' and d != 'obj' and d != 'bin']
    for fname in files:
        if fname.endswith('.cs') and 'Compatibility' in root:
            path = os.path.join(root, fname)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            new_content = fix_null_coalesce_in_expressions(content)
            if new_content != content:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f'Fixed null coalesce expression: {path}')
                count += 1

print(f'\nTotal files fixed: {count}')
