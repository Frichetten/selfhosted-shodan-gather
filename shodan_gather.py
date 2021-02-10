#!/usr/bin/env python3

# Simple tool to pull searches from Shodan and store them in a sqlite db

import os
import sys
import argparse
import requests
from shodan import Shodan
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy_declarations import System, Base


# List of titles to search for
TITLES = [
    "Grafana",
    "Nextcloud",
    "Firefly III",
    "Pi-hole",
    "Sonarr",
    "Radarr",
    "Lidarr",
    "Traefik",
    "Home Assistant",
    "qBittorrent",
    "Deluge",
    "Gitea",
    "Jackett",
    "Kibana",
    "Keycloak",
    "Bitwarden"
]

# Get the Shodan API key or exit
SHODAN_API_KEY = os.getenv('SHODAN_KEY')
if not SHODAN_API_KEY:
    print("[!] Need Shodan API key as SHODAN_KEY environment variable")
    print("[!] Exiting")
    sys.exit(1)

# Create api object
api = Shodan(SHODAN_API_KEY)

def search_title(title, page):
    try:
        # Returns a dict with 'matches' and 'total'
        # Pages start a 1
        results = api.search(f"title:\"{title}\"", page=page)
        return results
    except shodan.APIError as e:
        print(f"Error: {e}")
        sys.exit(2)

def import_page(page, session):
    for result in page:
        manage_result(result, session)

def manage_result(result, session):
    # Check if it is already in the DB
    shodan_id = result['_shodan']['id']
    if bool(session.query(System).filter_by(shodan_id=shodan_id).first()):
        # Exists, do nothing
        None
    else:
        import_result(result, session)

def import_result(result, session):
    ssl = False
    ssl_cn = ""
    hostname = ""

    if len(result['hostnames']) > 0:
        hostname = result['hostnames'][0]

    if "ssl" in result.keys():
        ssl = True
        try:
            ssl_cn = result['ssl']['cert']['subject']['CN']
        except KeyError:
            ssl_cn = ""

    new_system = System(
        software_name = TITLES[3],
        ip_str = result['ip_str'],
        ip = result['ip'],
        hostname = hostname,
        timestamp = result['timestamp'],
        asn = result['asn'],
        port = result['port'],
        location = result['location']['country_name'],
        title = result['http']['title'],
        shodan_id = result['_shodan']['id'],
        ssl = ssl,
        ssl_cn = ssl_cn
    )
    
    session.add(new_system)

def create_db():
    engine = create_engine('sqlite:///selfhosted.db')
    Base.metadata.create_all(engine)

def create_db_session():
    engine = create_engine('sqlite:///selfhosted.db')
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    return DBSession()

def main():
    print("Welcome to the SelfHosted Shodan Gatherer!")

    # Create DB connection
    session = create_db_session()

    for software in TITLES:
        # Get first page to see the total
        results = search_title(software, 1)
        total = results['total']
        print(f"{software}: {total} instances")
        import_page(results['matches'], session)
        
        # Based on that total we iterate through all pages
        total_pages = total // 100 + (total % 100 > 0)
        for page in range(2, total_pages+1):
            results = search_title(software, page)
            import_page(results['matches'], session)

    session.commit()


if __name__ == "__main__":
    main()