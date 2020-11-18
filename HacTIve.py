#!/usr/bin/env python3
import argparse
import subprocess
import re
from rich.console import Console
from rich.table import Table
import urllib.request
from urllib.parse import urlparse


console = Console()
reverse_whois_pattern = re.compile(r'<tr><td>([^<^>]*)</td><td>([^<^>]*)</td><td>([^<^>]*)</td></tr>')


class Logger:

    @staticmethod
    def info(message):
        console.print(f"[[cyan]![/cyan]] {message}")

    @staticmethod
    def title(message):
        console.print(f"\n[[cyan]*[/cyan]] [cyan]{message}[/cyan]\n")

    @staticmethod
    def success(message):
        console.print(f"[[green]+[/green]] {message}")

    @staticmethod
    def failure(message):
        console.print(f"[[red]-[/red]] {message}")


def get_command_output(command):
    split_command = command.split()  # check_output needs an array so we split the string
    output = subprocess.check_output(split_command)
    return output.decode('utf-8')


def perform_whois(domain):
    Logger.title(f"WHOIS Domain {domain}")  # passes value to info method in logger which handles it as message despite being called domain here
    output = get_command_output(f"whois {domain}")
    print(output)
    Logger.success("WHOIS Checks Complete")


def perform_dns(domain):
    Logger.title(f"DNS Info {domain}")
    output = get_command_output(f"dig all {domain}")
    print(output)
    Logger.title(f"DNS Mail Records {domain}")
    output = get_command_output(f"dig mx {domain}")
    print(output)
    Logger.success("DNS Checks Complete")


def perform_cert_transparency(domain, subdomain_list):
    Logger.title(f"Certificate Transparency {domain}")
    output = get_command_output(f"curl -fsSL https://crt.sh/?CN=%25.{domain}")
    for line in output.split():
        if domain in line and "TD" in line:
            subdomain = line.replace("<TD>", "").replace("</TD>", "").replace("'", "").strip()
            subdomain_list.add(subdomain.lower())
    Logger.success("Certificate Transparency Checks Complete")


def perform_reverse_whois(domain, subdomain_list):
    company = domain[:domain.index(".")]  # String slicing
    Logger.title(f"Reverse WHOIS on {company}")  # passes value to info method in logger which handles it as message despite being called domain here
    url = (f"https://viewdns.info/reversewhois/?q={company}")  # hardcode the base url for reverse whois and pass the domain as a parameter
    header = {"User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko"}  # hardcode the user agent header otherwise service does not accept the request
    request = urllib.request.Request(url, headers=header)  # Make/create the request using the previously set url and header parameters
    response = urllib.request.urlopen(request)  # Open the request object and write its contents to the response object
    results = reverse_whois_pattern.findall(response.read().decode('utf-8'))
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Domain")
    table.add_column("Date")
    table.add_column("Registrar")
    for result in results:
        table.add_row(result[0], result[1], result[2])
        subdomain_list.add(result[0].strip().lower())
    console.print(table)
    Logger.success("Reverse WHOIS Checks Complete")


def create_arg_parser():
    parser = argparse.ArgumentParser(description='HackTIve Threat Intelligence Framework')  # Check argparse docs, sets default value description to custom value and prints
    parser.add_argument("-d", "--domain", help="The domain to perform TI against")  # Sets custom argument settings for the script, if -d is not passed it prints help
    return parser


def print_all_subdomains(subdomain_list):
    Logger.title(f"Curated list of subdomains")
    print("\n".join(sorted(subdomain_list)))


def main():
    parser = create_arg_parser()
    args = parser.parse_args()

    if args.domain is not None:
        Logger.info(f"Domain is {args.domain}")
        perform_whois(args.domain)
        perform_dns(args.domain)
        subdomain_list = set()
        perform_cert_transparency(args.domain, subdomain_list)
        perform_reverse_whois(args.domain, subdomain_list)
        print_all_subdomains(subdomain_list)
    else:
        Logger.failure("Invalid arguments")
        parser.print_help()


if __name__ == "__main__":
    main()
