#!/usr/bin/env python3


import argparse
import subprocess


class Logger:

    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    ENDC = '\033[0m'

    @staticmethod
    def info(message):
        print("[%s*%s] %s" % (Logger.BLUE, Logger.ENDC, message))

    @staticmethod
    def success(message):
        print("[%s+%s] %s" % (Logger.GREEN, Logger.ENDC, message))

    @staticmethod
    def failure(message):
        print("[%s-%s] %s" % (Logger.RED, Logger.ENDC, message))


'''
Runs a command and returns the output as a string
'''
def get_command_output(command):
    return subprocess.check_output(command.split(" ")).decode('utf-8')


'''
Perform WHOIS lookup against target domain
'''
def perform_whois(domain):
    Logger.info("WHOIS Domain %s" % domain)
    print(get_command_output("whois %s" % domain))


'''
Create an arg parser for handling the program arguments.
'''
def create_arg_parser():
    parser = argparse.ArgumentParser( description='HackTIve Threat Intelligence Framework')
    parser.add_argument("-d", "--domain", help="The domain to perfrom TI against")
    return parser


'''
Main method
'''
def main():
    parser = create_arg_parser()
    args = parser.parse_args()

    if args.domain is not None:
        print("Domain is %s" % args.domain)
        perform_whois(args.domain)
    else:
        Logger.failure("Invalid arguments")
        parser.print_help()


'''
Entry point
'''
if __name__ == "__main__":
    main()
