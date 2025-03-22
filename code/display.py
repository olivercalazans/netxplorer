# MIT License
# Copyright (c) 2024 Oliver Calazans
# Repository: https://github.com/olivercalazans/netxplorer
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software...


def green(message:str) -> str:
    return '\033[32m' + message + '\033[0m'

def red(message:str) -> str:
    return '\033[31m' + message + '\033[0m'

def yellow(message:str) -> str:
    return '\033[33m' + message + '\033[0m'

def display_error(error:str) -> None:
    print(F'{yellow("ERROR")}: {error}')

def display_unexpected_error(error:str) -> None:
    print(f'{red("Unexpected error")}: {error}')

def display_process_stopped() -> None:
    print(red('Process stopped'))


# BANNER GRABBING ================================
def ok_icon() -> str:
    return f'[{green("+")}]'

def err_icon() -> str:
    return f'[{red("x")}]'

def display_bgrab_error(message:str, error:str) -> None:
    print(f'{err_icon()} {yellow(message)}: {error}')