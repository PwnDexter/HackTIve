#!/usr/bin/env python3


import argparse
import subprocess
import urllib.request
import requests

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
    split_command = command.split() # check_output needs an array so we split the string
    output = subprocess.check_output(split_command)
    return output.decode('utf-8')


'''
Perform WHOIS lookup against target domain
'''
def perform_whois(domain):
    Logger.info("WHOIS Domain %s" % domain) # passes value to info method in logger which handles it as message despite being called domain here
    output = get_command_output("whois %s" % domain)
    print(output)


'''
Perform Reverse WHOIS lookup against target domain
curl -v https://viewdns.info/reversewhois/\?q\=nettitude.com --header 'User-agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko'
'''
def perform_reverse_whois(domain):
    Logger.info("Reverse WHOIS Domain %s" % domain) # passes value to info method in logger which handles it as message despite being called domain here
    url = ("https://viewdns.info/reversewhois/?q=%s" % domain)
    header = {"User-Agent" : "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko"}
    print(url, header)
    request = urllib.request.Request(url, headers=header)
    response = urllib.request.urlopen(request)
    results = response.read()
    print(results)


'''
Perform DNS lookup against target domain
'''
def perform_dns(domain):
    Logger.info("DNS Info %s" % domain)
    output = get_command_output("dig all %s" % domain)
    print(output)


'''
Create an arg parser for handling the program arguments.
'''
def create_arg_parser():
    parser = argparse.ArgumentParser(description='HackTIve Threat Intelligence Framework') # Check argparse docs, sets default value description to custom value and prints
    parser.add_argument("-d", "--domain", help="The domain to perform TI against") # Sets custom argument settings for the script, if -d isnt passed it prints help
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
        perform_dns(args.domain)
        perform_reverse_whois(args.domain)
    else:
        Logger.failure("Invalid arguments")
        parser.print_help()


'''
Entry point
'''
if __name__ == "__main__":
    main()
