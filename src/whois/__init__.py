#!/usr/bin/env python3

import argparse
import requests
import json

# ANSI formatting
BOLD = '\033[1m'
ENDC = '\033[0m'
GREEN = '\033[92m'
RED = '\033[91m'
CYAN = '\033[38;5;51m'
__version__ = "1.0.0"

def main():
    args = parse_args()

    if args.version:
        print(f"{BOLD}rdap-pretty v{__version__}{ENDC}")
        return

    ip = args.ip
    data = fetch_rdap(ip)
    if not data:
        print(f"{RED}Error fetching RDAP data for {ip}{ENDC}")
        return

    print_summary(data, ip)


def parse_args():
    parser = argparse.ArgumentParser(
        prog="rdap-pretty",
        description="Pretty printer for IP WHOIS info using RDAP JSON"
    )
    parser.add_argument("ip", help="IP address to look up")
    parser.add_argument("-v", "--version", action="store_true", help="Show version and exit")
    return parser.parse_args()


def fetch_rdap(ip):
    try:
        response = requests.get(f"https://rdap.arin.net/registry/ip/{ip}", timeout=10)
        return response.json() if response.status_code == 200 else None
    except requests.RequestException:
        return None


def extract_field(data, path, default="N/A"):
    """Navigate nested JSON safely using a list path"""
    try:
        for key in path:
            if isinstance(key, int):
                data = data[key]
            else:
                data = data.get(key, {})
        return data if isinstance(data, str) else str(data)
    except Exception:
        return default


def get_entity_field(data, role, vcard_key):
    """Find an entity by role and extract a vCard field"""
    for entity in data.get("entities", []):
        if role in entity.get("roles", []):
            for entry in entity.get("vcardArray", [[], []])[1]:
                if entry[0] == vcard_key:
                    return entry[3]
    return "N/A"


def print_summary(data, ip):
    print(f"\n{BOLD}WHOIS Summary for {ip}{ENDC}\n")

    # Highlight IP block information
    cidr = f"{extract_field(data, ['cidr0_cidrs', 0, 'v4prefix'])}/{extract_field(data, ['cidr0_cidrs', 0, 'length'])}"
    ip_range = f"{data.get('startAddress')} - {data.get('endAddress')}"
    print_line("CIDR", f"{BOLD}{cidr}{ENDC}")
    print_line("IP Range", f"{BOLD}{ip_range}{ENDC}")

    # Highlight network identity
    print_line("Net Name", f"{CYAN}{data.get('name', 'N/A')}{ENDC}")
    print_line("Organization", f"{CYAN}{get_entity_field(data, 'registrant', 'fn')}{ENDC}")

    # Everything else: neutral
    print_line("Country", get_entity_field(data, "registrant", "adr"))
    print_line("Status", ", ".join(data.get("status", [])))
    print_line("Registered", extract_event(data, "registration"))
    print_line("Last Updated", extract_event(data, "last changed"))
    print_line("Geofeed", extract_geofeed(data))
    print_line("Abuse Email", get_entity_field(data, "abuse", "email"))
    print_line("Tech Contact", get_entity_field(data, "technical", "email"))

    print(f"\nSource: {extract_field(data, ['links', 0, 'href'])}")


    # print(f"\n{BOLD}WHOIS Summary for {ip}{ENDC}\n")
    # print_line("CIDR", f"{extract_field(data, ['cidr0_cidrs', 0, 'v4prefix'])}/{extract_field(data, ['cidr0_cidrs', 0, 'length'])}")
    # print_line("IP Range", f"{data.get('startAddress')} - {data.get('endAddress')}")
    # print_line("Net Name", data.get("name", "N/A"))
    # print_line("Organization", get_entity_field(data, "registrant", "fn"))
    # print_line("Country", get_entity_field(data, "registrant", "adr"))
    # print_line("Status", ", ".join(data.get("status", [])))
    # print_line("Registered", extract_event(data, "registration"))
    # print_line("Last Updated", extract_event(data, "last changed"))
    # print_line("Geofeed", extract_geofeed(data))
    # print_line("Abuse Email", get_entity_field(data, "abuse", "email"))
    # print_line("Tech Contact", get_entity_field(data, "technical", "email"))

    # print(f"\n{CYAN}Source: {extract_field(data, ['links', 0, 'href'])}{ENDC}")


def extract_event(data, event_name):
    for event in data.get("events", []):
        if event.get("eventAction") == event_name:
            return event.get("eventDate", "N/A")
    return "N/A"


def extract_geofeed(data):
    for remark in data.get("remarks", []):
        if remark.get("title") == "Registration Comments":
            return remark.get("description", ["N/A"])[0]
    return "N/A"


def print_line(label, value, width=24):
    print(f"\t{BOLD}{label}:{ENDC}".ljust(width), value)


if __name__ == "__main__":
    main()
