#!/usr/bin/env python3
import os
import re

def fix_primary_constructor(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Pattern: class Name(param1, param2) : Base(...)
    # We need to find the class declaration and convert it
    
    # Multi-line class declaration pattern
    pattern = r'(public|internal|private|protected)(\s+sealed|\s+partial|\s+abstract)?\s+class\s+(\w+)\s*\(((?:[^)]|\n)*?)\)\s*(?::\s*([^\n{]+))?'
    
    def replace_primary_constructor(match):
        visibility = match.group(1)
        modifiers = match.group(2) or ''
        class_name = match.group(3)
        params = match.group(4)
        base_clause = match.group(5) if match.group(5) else ''
        
        # Parse parameters
        param_list = []
        for param in params.split(','):
            param = param.strip()
            if param:
                param_list.append(param)
        
        # Build the new class declaration
        result = f'{visibility}{modifiers} class {class_name}'
        
        # Check if we have a base class with parameters
        has_base_with_params = base_clause and '(' in base_clause
        
        if has_base_with_params:
            # Extract base class and its parameters
            base_match = re.match(r'\s*(\w+)\s*\((.*?)\)(.*)' , base_clause)
            if base_match:
                base_class = base_match.group(1)
                base_params = base_match.group(2)
                rest = base_match.group(3)
                result += f' : {base_class}{rest}\n{{\n'
                result += f'    public {class_name}({", ".join(param_list)})\n'
                result += f'        : base({base_params})\n'
                result += '    {\n'
                result += '    }\n'
            else:
                result += f' : {base_clause}\n{{\n'
                result += f'    public {class_name}({", ".join(param_list)})\n'
                result += '    {\n'
                result += '    }\n'
        elif base_clause:
            # Base class without parameters
            result += f' : {base_clause}\n{{\n'
            # Build constructor body - store fields
            result += f'    private readonly {param_list[0].rsplit(" ", 1)[0]} _{param_list[0].rsplit(" ", 1)[1].lstrip("_")};\n'
            if len(param_list) > 1:
                result += f'    private readonly {param_list[1].rsplit(" ", 1)[0]} _{param_list[1].rsplit(" ", 1)[1].lstrip("_")};\n'
            result += f'\n    public {class_name}({", ".join(param_list)})\n'
            result += '    {\n'
            for param in param_list:
                parts = param.rsplit(' ', 1)
                if len(parts) == 2:
                    param_name = parts[1]
                    result += f'        _{param_name.lstrip("_")} = {param_name};\n'
            result += '    }\n'
        else:
            # No base class
            result += '\n{\n'
            # Build constructor body - store fields
            for param in param_list:
                parts = param.rsplit(' ', 1)
                if len(parts) == 2:
                    param_type = parts[0]
                    param_name = parts[1]
                    result += f'    private readonly {param_type} _{param_name.lstrip("_")};\n'
            result += f'\n    public {class_name}({", ".join(param_list)})\n'
            result += '    {\n'
            for param in param_list:
                parts = param.rsplit(' ', 1)
                if len(parts) == 2:
                    param_name = parts[1]
                    result += f'        _{param_name.lstrip("_")} = {param_name};\n'
            result += '    }\n'
        
        return result
    
    new_content = re.sub(pattern, replace_primary_constructor, content)
    
    if new_content != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        return True
    return False

# Process all files
repo = '/home/runner/work/ksef-client-csharp48/ksef-client-csharp48'
count = 0
for root, dirs, files in os.walk(repo):
    dirs[:] = [d for d in dirs if d != '.git' and d != 'obj' and d != 'bin']
    for fname in files:
        if fname.endswith('.cs') and fname != 'ClientBase.cs':
            path = os.path.join(root, fname)
            if fix_primary_constructor(path):
                print(f'Fixed: {path}')
                count += 1

print(f'\nTotal files fixed: {count}')
