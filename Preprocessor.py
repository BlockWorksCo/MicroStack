
import re
import sys


g={}
l={}

def Run(pythonText):
    exec(compile(pythonText, '<EmbeddedPython>','exec'), g)
    try:
        result  = str(g['t'])
    except KeyError:
        result  = sourceText
    return result


def ReplaceEmbeddedPython(matchobj):
    pythonText  = 't='+matchobj.group(1)
    return Run(pythonText)

sourceText  = open(sys.argv[1]).read()

macros              = re.compile('#ifdef\s+PREPROCESSOR(.*?)#endif',re.MULTILINE|re.DOTALL).findall(sourceText)
macros              = ''.join(macros)
sourceText          = re.sub('#ifdef\s+PREPROCESSOR[\d\D]*?#endif','#define PREPROCESSED',sourceText, re.DOTALL|re.MULTILINE)

print(macros)
g['sourceText']     = sourceText
exec(compile(macros, '<EmbeddedPython>','exec'), g)
sourceText          = g['sourceText']
#sourceText          = Run(macros)
sourceText          = re.sub('!(.*?)!', ReplaceEmbeddedPython, sourceText)

print(sourceText)
