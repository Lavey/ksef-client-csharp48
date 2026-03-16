#!/usr/bin/env python3
import os
import re

def transform_file(content, filepath):
    # Remove nullable directives
    content = re.sub(r'^\s*#nullable\s+(enable|disable|restore).*$', '', content, flags=re.MULTILINE)
    
    # Remove global using
    content = re.sub(r'^global using.*;\s*$', '', content, flags=re.MULTILINE)
    
    # Remove required keyword
    content = re.sub(r'\brequired\s+', '', content)
    
    # init -> set
    content = re.sub(r'\binit\b', 'set', content)
    
    # Remove [MemberNotNull...] attributes
    content = re.sub(r'\[MemberNotNull[^\]]*\]\s*', '', content)
    
    # ValueTask<T> -> Task<T>
    content = re.sub(r'\bValueTask\b', 'Task', content)
    
    # ??= operator - need to be careful about multiline
    def replace_null_coalesce_assign(match):
        var = match.group(1)
        value = match.group(2)
        return f'if ({var} == null) {var} = {value};'
    content = re.sub(r'(\w+)\s*\?\?=\s*([^;]+);', replace_null_coalesce_assign, content)
    
    # is not null -> != null
    content = re.sub(r'\bis not null\b', '!= null', content)
    # is null -> == null  
    content = re.sub(r'\bis null\b', '== null', content)
    
    # Remove nullable ? from reference types in common patterns
    # string? -> string
    content = re.sub(r'\bstring\?', 'string', content)
    # object? -> object  
    content = re.sub(r'\bobject\?', 'object', content)
    # Remove ? from generic type patterns
    content = re.sub(r'(IEnumerable<[^>]+>)\?', r'\1', content)
    content = re.sub(r'(IList<[^>]+>)\?', r'\1', content)
    content = re.sub(r'(List<[^>]+>)\?', r'\1', content)
    content = re.sub(r'(Dictionary<[^>]+>)\?', r'\1', content)
    content = re.sub(r'(Task<[^>]+>)\?', r'\1', content)
    content = re.sub(r'(ICollection<[^>]+>)\?', r'\1', content)
    content = re.sub(r'(IEnumerable)\?', r'\1', content)
    content = re.sub(r'(X509Certificate2)\?', r'\1', content)
    content = re.sub(r'(Action[^?<\s]*?)\?(?=[\s,);])', r'\1', content)
    content = re.sub(r'(Func<[^>]+>)\?', r'\1', content)
    content = re.sub(r'(Timer)\?', r'\1', content)
    content = re.sub(r'(SemaphoreSlim)\?', r'\1', content)
    content = re.sub(r'(HttpClient)\?', r'\1', content)
    content = re.sub(r'(HttpResponseMessage)\?', r'\1', content)
    content = re.sub(r'(JsonSerializerOptions)\?', r'\1', content)
    content = re.sub(r'(CancellationToken)\?', r'\1', content)
    content = re.sub(r'(Exception)\?', r'\1', content)
    content = re.sub(r'(StringBuilder)\?', r'\1', content)
    content = re.sub(r'(Stream)\?', r'\1', content)
    content = re.sub(r'(MemoryStream)\?', r'\1', content)
    content = re.sub(r'(byte\[\])\?', r'\1', content)
    
    return content

repo = '/home/runner/work/ksef-client-csharp48/ksef-client-csharp48'
count = 0
for root, dirs, files in os.walk(repo):
    dirs[:] = [d for d in dirs if d != '.git' and d != 'obj' and d != 'bin']
    for fname in files:
        if fname.endswith('.cs'):
            path = os.path.join(root, fname)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            new_content = transform_file(content, path)
            if new_content != content:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f'Transformed: {path}')
                count += 1

print(f'\nTotal files transformed: {count}')
