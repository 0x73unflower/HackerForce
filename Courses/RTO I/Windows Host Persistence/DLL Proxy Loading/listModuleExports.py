import sys
import pefile

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <module> <modulepath>")
    sys.exit(1)

module = sys.argv[1]
try:
    modulePath = sys.argv[2]
except IndexError:
    modulePath = None

pe = pefile.PE(module)

for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if symbol.name:
	    symbol = symbol.name.decode("UTF-8")
	    print(f'#pragma comment(linker, "/export:{symbol}={module[:-4]}.{symbol}")')
	    if modulePath:
	        print(f'#pragma comment(linker, "/export:{symbol}={modulePath}{module[:-4]}.{symbol}")')
