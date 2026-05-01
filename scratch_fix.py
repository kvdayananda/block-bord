import os, glob, re

for fpath in glob.glob('backend/app/routers/*.py'):
    with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Simple regex to fix TemplateResponse
    # templates.TemplateResponse("name.html", {"request": request, "other": var})
    # to
    # templates.TemplateResponse(request, "name.html", {"other": var})
    
    def replacer(match):
        name = match.group(1)
        context_str = match.group(2)
        
        # Remove '"request": request' or "'request': request"
        # Since it's formatted in different ways, we'll use regex to remove it
        context_str = re.sub(r'[\'"]request[\'"]\s*:\s*request\s*,?', '', context_str).strip()
        if context_str.endswith(','):
            context_str = context_str[:-1].strip()
            
        if context_str:
            return f'templates.TemplateResponse(request, {name}, {{{context_str}}})'
        else:
            return f'templates.TemplateResponse(request, {name})'
            
    # Also handle the multiline cases manually if there are any
    # So far the warnings only happen during test suite runs
    new_content = re.sub(r'templates\.TemplateResponse\(\s*([\'"][^\'"]+[\'"])\s*,\s*\{(.*?)\}\s*\)', replacer, content, flags=re.DOTALL)
    
    if new_content != content:
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Fixed {fpath}")
