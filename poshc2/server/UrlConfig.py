import random
import sys
from urllib.parse import urlparse

from poshc2 import Colours


class UrlConfig:
    def __init__(self, filepath="", wordlist="wordlist.txt", use_http=False):

        self.filepath = filepath
        self.url_list = []
        self.sockList = []
        self.sockRewriteList = []
        self.urlRewriteList = []
        self.rewriteFile = "rewrite-rules.txt"
        self.use_http = use_http
        if filepath != "":
            self.wordList = ""
            self.build_urls()
        else:
            self.wordList = open(wordlist).read().splitlines()
            self.get_random_urls()

        self.qcUrl = ""
        self.connUrl = ""
        self.get_socks_urls()  # Ordering is important. getUrls/getRandomUrls before getSockUrls or getSockurls has nothing to operate on.
        self.create_rewrite_rules()
        self.create_socks_rewrite_rules()

    def create_socks_rewrite_rules(self):
        # Setter
        for sockurl in self.sockList:
            if self.use_http:
                self.sockRewriteList.append("RewriteRule ^/" + urlparse(sockurl).path + "(.*) http://${SharpSocks}/" + urlparse(sockurl).path + "$1 [NC,L,P]")
            else:
                self.sockRewriteList.append("RewriteRule ^/" + urlparse(sockurl).path + "(.*) https://${SharpSocks}/" + urlparse(sockurl).path + "$1 [NC,L,P]")

    def create_rewrite_rules(self):
        # Setter
        for url in self.url_list:
            if self.use_http:
                self.urlRewriteList.append("RewriteRule ^/" + urlparse(url).path + "(.*) http://${PoshC2}/" + urlparse(url).path + "$1 [NC,L,P]")
            else:
                self.urlRewriteList.append("RewriteRule ^/" + urlparse(url).path + "(.*) https://${PoshC2}/" + urlparse(url).path + "$1 [NC,L,P]")

    def get_socks_urls(self):
        sock1 = random.choice(self.url_list)
        self.url_list[:] = (value for value in self.url_list if value != sock1)
        sock2 = random.choice(self.url_list)
        self.url_list[:] = (value for value in self.url_list if value != sock2)
        self.sockList = [sock1, sock2]

    @staticmethod
    def process_url(line):
        output = urlparse(line).path.rstrip().lstrip('/').strip()
        if not output:
            return None
        output = output.replace("'", "")
        if output[-1] != "/":
            output = output + "/"
        return output

    def build_urls(self):
        with open(self.filepath, "r") as f:
            array = []
            for line in f:
                to_append = self.process_url(line)
                if to_append:
                    processed = self.process_url(line)
                    if processed:
                        array.append(processed)
            self.url_list = list(set(array))
        if len(self.url_list) < 3:
            print(f"{Colours.RED}Please add three or more URLs to the url list at resources/urls.txt (the more the better){Colours.END}")
            sys.exit(1)

    def generate_random_url(self):
        words = self.wordList
        length_of_url = random.randint(1, 10)
        i = 0  # Length of URL
        url_stub = ""
        while i < length_of_url:
            i = i + 1
            url_stub = url_stub + random.choice(words) + "/"

        if random.randint(0, 1) == 1:
            url_stub = url_stub + random.choice(words) + "?" + random.choice(words) + "=" + random.choice(words)
            url_stub = url_stub.replace("'", "")
            return url_stub
        else:
            url_stub = url_stub.replace("'", "")
            return url_stub

    def get_random_urls(self):
        num_of_urls = random.randint(20, 75)
        i = 0
        while i < num_of_urls:
            i = i + 1
            self.url_list.append(self.generate_random_url())

    def get_urls(self):
        return '"{0}"'.format('", "'.join(self.url_list))

    def get_socks(self):
        return '"{0}"'.format('", "'.join(self.sockList))

    def get_rewrite_rules(self):
        return self.urlRewriteList

    def get_socks_rewrite_rules(self):
        return self.sockRewriteList

    def get_hosted_file_url(self):
        if self.wordList == "":
            return random.choice(self.url_list)
        else:
            return random.choice(self.url_list) + random.choice(self.wordList) + "?" + random.choice(self.wordList) + "=" + random.choice(self.wordList)

    def get_connect_url(self):
        if self.wordList == "":
            return random.choice(self.url_list)
        else:
            return random.choice(self.url_list) + random.choice(self.wordList) + "?" + random.choice(self.wordList) + "=" + random.choice(self.wordList)
