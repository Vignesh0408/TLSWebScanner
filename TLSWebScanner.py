import argparse
import time
import requests
import ssl
import socket
import urllib.parse
from bs4 import BeautifulSoup
from collections import deque
from urllib.robotparser import RobotFileParser

ascii_art = """
████████╗██╗     ███████╗██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
╚══██╔══╝██║     ██╔════╝██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
   ██║   ██║     ███████╗██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
   ██║   ██║     ╚════██║██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
   ██║   ███████╗███████║╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
   ╚═╝   ╚══════╝╚══════╝ ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                                                                               """

print(ascii_art)

class Crawler:
    def __init__(self, seed_urls, depth, max_sites=10, tls_only=False):
        self.queues = {url: deque([url]) for url in seed_urls}
        self.depth = depth
        self.max_depth = depth
        self.max_sites = max_sites
        self.crawled_counts = {url: 0 for url in seed_urls}
        self.visited = {url: set() for url in seed_urls}
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
        }
        self.tls_only = tls_only
        self.output_file = None

    def Robot_crawl(self, url):
        robot_parser = RobotFileParser()
        robot_parser.set_url(urllib.parse.urljoin(url, '/robots.txt'))
        robot_parser.read()
        return robot_parser.can_fetch(self.headers["User-Agent"], url)

    def start(self):
        self.output_file = open("output.txt", "w", encoding="utf-8")
        for seed_url in self.queues.keys():
            self.output_file.write(f"Results for {seed_url}\n")
            self.output_file.write("=" * 40 + "\n")
            while self.queues[seed_url] and self.crawled_counts[seed_url] < self.max_sites:
                url = self.queues[seed_url].popleft()
                if self.Robot_crawl(url):
                    self.crawl(seed_url, url)
                    self.crawled_counts[seed_url] += 1
            self.output_file.write("=" * 40 + "\n\n")
        self.output_file.close()

    def crawl(self, seed_url, url):
        if url in self.visited[seed_url]:
            return

        self.visited[seed_url].add(url)

        print(f"Unleashing the Crawling on {url}")
        time.sleep(1)

        try:
            response = requests.get(url, headers=self.headers)
        except requests.RequestException:
            return

        if response.status_code != 200:
            return

        soup = BeautifulSoup(response.text, "html.parser")
        tls_version, cipher_suite = self.get_tls_info(url)
        if self.tls_only and not tls_version:
            return

        self.process_page(url, soup, tls_version, cipher_suite)

        links = soup.find_all("a")
        for link in links:
            href = link.get("href")
            if href and href.startswith("http") and href not in self.visited[seed_url]:
                self.queues[seed_url].append(href)

    def get_tls_info(self, url):
        hostname = urllib.parse.urlparse(url).hostname
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.version(), ssock.cipher()[0]
        except (ssl.SSLError, socket.gaierror):
            return None, None

    def process_page(self, url, soup, tls_version, cipher_suite):
        title = soup.title.string.strip() if soup.title else ""
        self.output_file.write(f"Inspecting Site: {url}\nTitle: {title}\n")

        if tls_version:
            self.output_file.write(f"Identified TLS Version: {tls_version}\nCipher Suite: {cipher_suite}\n")
            self.output_vulnerabilities(tls_version)

        self.output_file.write("\n")

    def output_vulnerabilities(self, tls_version):
        tls_vulnerabilities = {
            "1.1": [
                ("Your in Danger Environment", "Please Do upgrade your Version to version 1.2."),
                ("POODLE ATTACK", "Enables a man-in-the-middle attack to decrypt encrypted data due to improper padding."),
                ("BEAST ATTACK", "The BEAST attack exploits vulnerabilities in the CBC mode of encryption in TLS 1.1."),
            ],
            "1.2": [
                ("Your in Danger Environment", "Please Do upgrade your Version to version 1.3."),
                ("CRIME attack", "Leverages TLS data compression to steal information."),
                ("BREACH attack", "Targets HTTP responses, exploiting data compression to steal data."),
                ("SWEET32", "Vulnerability to birthday attacks with older block ciphers."),
                ("DROWN Attack", "Allows decryption of sessions if server supports SSLv2."),
                ("RC4 Cipher Attack", "Vulnerabilities with RC4 cipher, enabling plaintext recovery.")
            ],
            "1.3": [
                ("!!! You're Using a safe TLS Version.", "!!!")
            ]
        }

        if tls_version:
            self.output_file.write(f"............................{tls_version} Possible Vulnerabilities.............................\n")
            vulnerabilities = tls_vulnerabilities.get(tls_version[4:], [])
            for vulnerability in vulnerabilities:
                self.output_file.write(f"{vulnerability[0]}! {vulnerability[1]}\n")
            self.output_file.write("\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web crawler")
    parser.add_argument("seed_urls", type=str, nargs="+", help="List of seed URLs")
    parser.add_argument("depth", type=int, help="The depth to crawl")
    parser.add_argument("--tls", action="store_true", help="Crawl only sites that support TLS")
    args = parser.parse_args()

    depth = args.depth
    seed_urls = args.seed_urls
    tls_only = args.tls

    crawler = Crawler(seed_urls, depth, tls_only=tls_only)

    print("Cyber Exploration Underway")
    crawler.start()
    print("Mission Accomplished")
