from colorama import init, Fore, Style
 
init()
 
SESSION1 = Fore.CYAN
SESSION2 = Fore.YELLOW
ATTACK   = Fore.WHITE
SUCCESS  = Fore.GREEN
RESET    = Style.RESET_ALL
 
def log(msg="", colour=""):
    print(f"{colour}[+] {msg}{RESET}" if msg else "")