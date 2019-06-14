#!/usr/bin/env python
import re, random, os.path
import urllib.parse
from urllib.parse import urlparse

class UrlConfig:
    #urlConfig class represents the necessary URL information for PoshC2.

    def __init__(self, filePath = "", wordList="wordlist.txt"):
        #by default a filepath is specified when instantiating the object
        #selecting urls from the old list.
        #Feel free to change it to work from a fixed list of known URLs
        #works a treat copying and pasting from burp.
        self.filePath = filePath
        self.urlList = []
        self.sockList = []
        self.sockRewriteList = []
        self.urlRewriteList = []
        self.rewriteFile = "rewrite-rules.txt"
        if filePath != "":
            self.wordList = ""
            self.getUrls()
        else:
            #If you remove the filepath, you'll get random word generation based on a wordlist.
            #Default Example Wordlist from:
            #https://raw.githubusercontent.com/dominictarr/random-name/master/first-names.txt 
            #Could use urllib to request this live, but opted for local storage here.
            self.wordList = open(wordList).read().splitlines()
            self.getRandomUrls()

        self.qcUrl = ""
        self.connUrl = ""
        self.getSockUrls() # Ordering is important. getUrls/getRandomUrls before getSockUrls or getSockurls has nothing to operate on.
        self.createRewriteRules()
        self.createSockRewriteRules()

#Internal functions - Intended to generate the various items.

    def createSockRewriteRules(self):
        #Setter
        for sockurl in self.sockList:
            self.sockRewriteList.append("RewriteRule ^/" + urlparse(sockurl).path + "(.*) https://${SharpSocks}/" + urlparse(sockurl).path + "$1 [NC,L,P]")

    def createRewriteRules(self):
        #Setter
        for url in self.urlList:
            self.urlRewriteList.append("RewriteRule ^/" + urlparse(url).path + "(.*) https://${PoshC2}/" + urlparse(url).path + "$1 [NC,L,P]")

    def getSockUrls(self):
        sock1 = random.choice(self.urlList)
        self.urlList[:] = (value for value in self.urlList if value != sock1)
        sock2 = random.choice(self.urlList)
        self.urlList[:] = (value for value in self.urlList if value != sock2)
        self.sockList = [ sock1, sock2 ]

    def process(self,line):
        output = urlparse(line).path
        output = output.rpartition('/')[0]
        output = output.replace("'", "")
        if output != '':
            if output[0] == "/":
                output = output.lstrip('/')
            if output[-1] != "/":
                output = output + "/"
        output = output.replace("'", "")
        return output

    def getUrls(self):
        with open(self.filePath, "r") as input:
            array = []
            for line in input:
                toAppend = self.process(line)
                if toAppend != '':
                    if toAppend != ' ':
                        array.append(self.process(line))
            self.urlList = list(set(array))
    
    def generateRandomURL(self):
        words = self.wordList
        lengthOfUrl = random.randint(1,10)
        i = 0 #Length of URL
        urlStub = ""
        while i < lengthOfUrl:
            i = i+1
            urlStub = urlStub + random.choice(words) + "/"

        if random.randint(0,1) == 1:
            urlStub = urlStub + random.choice(words) + "?" + random.choice(words) + "=" + random.choice(words)
            urlStub = urlStub.replace("'","")
            return urlStub
        else:
            urlStub = urlStub.replace("'","")
            return urlStub

    def getRandomUrls(self):
        numOfUrls = random.randint(20,75)
        i = 0
        while i < numOfUrls:
            i = i+1
            self.urlList.append(self.generateRandomURL())
        

#Outputs - Formatted to work with PoshC2
    def fetchUrls(self):
        return '"{0}"'.format('", "'.join(self.urlList))
    def fetchSocks(self):
        return '"{0}"'.format('", "'.join(self.sockList))
    def fetchRewriteRules(self):
        return self.urlRewriteList
    def fetchSocksRewriteRules(self):
        return self.sockRewriteList
    def fetchQCUrl(self):
        if self.wordList == "":
            return random.choice(self.urlList)
        else:
            return random.choice(self.urlList) + random.choice(self.wordList) + "?" + random.choice(self.wordList) + "=" + random.choice(self.wordList)
    def fetchConnUrl(self):
        if self.wordList == "":
            return random.choice(self.urlList)
        else:
            return random.choice(self.urlList) + random.choice(self.wordList) + "?" + random.choice(self.wordList) + "=" + random.choice(self.wordList)

