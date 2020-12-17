#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pycef
import json
import requests
import re
import csv
import sys
import os
import argparse
def flatten(A):
  rt = []
  for i in A:
    if isinstance(i,list): rt.extend(flatten(i))
    else: rt.append(i)
  return rt
def removeDuplicates(listofElements):
  uniqueList = []
  for elem in listofElements:
    if elem not in uniqueList:
      uniqueList.append(elem)
  return uniqueList
class DomainSquatting():
  def __init__(self, domain):
    self.domain, self.tld = self.__domain_tld(domain)
    self.domains = []
    self.keyboard = {
    '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
    'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
    'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
    'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
    }
  def __domain_tld(self, domain):
    domain = domain.rsplit('.', 2)
    if len(domain) == 2:
      return domain[0], domain[1]
  def __bitsquatting(self):
    result = []
    masks = [1, 2, 4, 8, 16, 32, 64, 128]
    for i in range(0, len(self.domain)):
      c = self.domain[i]
      for j in range(0, len(masks)):
        b = chr(ord(c) ^ masks[j])
        o = ord(b)
        if (o >= 48 and o <= 57) or (o >= 97 and o <= 122) or o == 45:
          result.append(self.domain[:i] + b + self.domain[i+1:])
    return result
  def __homoglyph(self):
    glyphs = {
    'b': ['d', 'lb'],
    'c': ['e'],
    'd': ['b', 'cl', 'dl'],
    'e': ['c'],
    'g': ['q'],
    'h': ['lh'],
    'i': ['1', 'l'],
    'k': ['lk', 'ik', 'lc'],
    'l': ['1', 'i'],
    'm': ['n', 'nn', 'rn', 'rr'],
    'n': ['m', 'r'],
    'o': ['0'],
    'q': ['g'],
    'u': ['v'],
    'v': ['u'],
    'w': ['vv', 'uu'],
    'z': ['s']
    }
    result_1pass = set()
    for ws in range(1, len(self.domain)):
      for i in range(0, (len(self.domain)-ws)+1):
        win = self.domain[i:i+ws]
        j = 0
        while j < ws:
          c = win[j]
          if c in glyphs:
            win_copy = win
            for g in glyphs[c]:
              win = win.replace(c, g)
              result_1pass.add(self.domain[:i] + win + self.domain[i+ws:])
              win = win_copy
          j += 1
        result_2pass = set()
    for domain in result_1pass:
      for ws in range(1, len(domain)):
        for i in range(0, (len(domain)-ws)+1):
          win = domain[i:i+ws]
          j = 0
          while j < ws:
            c = win[j]
            if c in glyphs:
              win_copy = win
              for g in glyphs[c]:
                win = win.replace(c, g)
                result_2pass.add(domain[:i] + win + domain[i+ws:])
                win = win_copy
            j += 1
        return list(result_1pass | result_2pass)

  def __hyphenation(self):
    result = []
    for i in range(1, len(self.domain)):
      result.append(self.domain[:i] + '-' + self.domain[i:])
    return result

  def __insertion(self):
    result = []
    for i in range(1, len(self.domain)-1):
        if self.domain[i] in self.keyboard:
          for c in self.keyboard[self.domain[i]]:
            result.append(self.domain[:i] + c + self.domain[i] + self.domain[i+1:])
            result.append(self.domain[:i] + self.domain[i] + c + self.domain[i+1:])
    return list(set(result))

  def __omission(self):
    result = []
    for i in range(0, len(self.domain)):
      result.append(self.domain[:i] + self.domain[i+1:])
    n = re.sub(r'(.)\1+', r'\1', self.domain)
    if n not in result and n != self.domain:
      result.append(n)
    return list(set(result))

  def __repetition(self):
    result = []
    for i in range(0, len(self.domain)):
      if self.domain[i].isalpha():
        result.append(self.domain[:i] + self.domain[i] + self.domain[i] + self.domain[i+1:])
    return list(set(result))

  def __replacement(self):
    result = []
    for i in range(0, len(self.domain)):
        if self.domain[i] in self.keyboard:
          for c in self.keyboard[self.domain[i]]:
            result.append(self.domain[:i] + c + self.domain[i+1:])
    return list(set(result))

  def __subdomain(self):
    result = []
    for i in range(1, len(self.domain)):
      if self.domain[i] not in ['-', '.'] and self.domain[i-1] not in ['-', '.']:
        result.append(self.domain[:i] + '.' + self.domain[i:])
    return result

  def __transposition(self):
    result = []
    for i in range(0, len(self.domain)-1):
      if self.domain[i+1] != self.domain[i]:
        result.append(self.domain[:i] + self.domain[i+1] + self.domain[i] + self.domain[i+2:])
    return result

  def __vowel_swap(self):
    vowels = 'aeiou'
    result = []
    for i in range(0, len(self.domain)):
      for vowel in vowels:
        if self.domain[i] in vowels:
          result.append(self.domain[:i] + vowel + self.domain[i+1:])
    return list(set(result))

  def __addition(self):
    result = []
    for i in range(97, 123):
      result.append(self.domain + chr(i))
    return result

  def generate(self):
    self.domains.append(self.domain)
    self.domains.append("www"+self.domain)
    self.domains.append(self.domain+self.tld)
    self.domains.append(self.__addition())
    self.domains.append(self.__bitsquatting())
    self.domains.append(self.__homoglyph())
    self.domains.append(self.__hyphenation())
    self.domains.append(self.__insertion())
    self.domains.append(self.__omission())
    self.domains.append(self.__repetition())
    self.domains.append(self.__replacement())
    self.domains.append(self.__subdomain())
    self.domains.append(self.__transposition())
    self.domains.append(self.__vowel_swap())
    flat = flatten(self.domains)
    self.domains=[]
    for i in flat:
      if i is not None:
       self.domains.append(i.encode('utf-8'))
    withoutduplicates=removeDuplicates(self.domains)
    self.domains=withoutduplicates

def test(name):
  valid=True
  try:
    unicode(name)
  except UnicodeDecodeError:
    valid=False
  return valid

def testdomain(uri):
  if not test(uri):
    try:
      return True
    except Exception as e:
      print e
      return False
  else:
    try:
      requests.get(uri)
      return True
    except Exception as e:
      return False

def testonmic(name):
  if testdomain('https://'+name):
    return True
  else:
    return False
def check_domain(domain):
  if testonmic(domain.rsplit(".")[0]+".sharepoint.com"):
    print "%s.sharepoint.com is up"%domain.split(".")[0]
  else:
    print "%s.sharepoint.com is down / not available"%domain.split(".")[0]
def output(domain,list,type):
  if type=="json":
    print "Saving output in JSON file"
    data= {"domainsdetected":list}
    with open("[O365Squatting]"+domain+"_report.json",'w') as outfile:
      json.dump(data,outfile)
    print "JSON file generated successfully!!!"
  if type=="csv":
    print "Saving output in CSV file"
    outputcsv=open('[O365Squatting]'+domain+'_report.csv','w')
    outputline=csv.writer(outputcsv,delimiter=',')
    outputline.writerow(['Domain','Detected'])
    for i in list:
      outputline.writerow([i.encode('utf-8'),'Detected!'])
    outputcsv.close()
    print "CSV file generated successfully!!"
  if type=="cef":
    print "Saving output in CEF format"
    f=open("[O365Squatting]"+domain+"CEF.log","w")
    listofentries=[]
    for i in list:
      entry='CEF:0|O365Squatting|O365 Squatting Script|1|2|Domain squatting in Microsoft detected|3| DomainDetected='+i
      f.write(str(pycef.parse(entry))+"\n")
    f.close()
    print "CEF log file generated succesfully!!!"

def single(domain, debug):
    if debug:
        print '[DEBUG] Generating list of all domains impersonating %s' \
            % domain
    domaingen = DomainSquatting(domain)
    domaingen.generate()
    domains = domaingen.domains
    listofdomains = []
    output = []
    if debug:
        print '[DEBUG] Printing all domains to be tested in Office365'
    for i in domains:
        listofdomains.append(i + '.sharepoint.com')
        if debug:
            print '[DEBUG] %s' % i
    for i in listofdomains:

#

        if debug:
            print '[DEBUG] testing %s' % i
        if testonmic(i):
            output.append(i)
            if debug:
                print '[DEBUG] %s is up' % i
            print i + ' detected'
    if debug:
        print '[DEBUG] Ending scan for %s' % domain
    return output

def showlogo():
  logo=""" 
  ____  ____ ____ ____ ____               __  __  _           
 / __ \\ _  // __// __// __/__ ___ _____ _/ /_/ /_(_)__  ___ _
/ /_/ //_ </ _ \\/__ \\_\\ \\/ _ `/ // / _ `/ __/ __/ / _ \\/ _ `/
\\____/____/\\___/____/___/\\_, /\\___/\\_,_/\\__/\\__/_/_//_/\\_, /
                          /_/                         /___/  

			Made by:
				Juan Francisco Bolívar (@jfran_cbit)
			       José Miguel Gómez-Casero (@MiguelGcm)
"""

  return logo

def main():
    requiredArgs = [
        '--help',
        '-h',
        '-d',
        '--domain',
        '-f',
        '--file',
        '-c',
        '--check-domain',
        ]

    print showlogo()

    parser = argparse.ArgumentParser(add_help=False,
            description='Search for potential domain squatting published on Microsoft Office365'
            )
    group1 = parser.add_argument_group('required',
            'required arguments (only one is required)')
    group2 = parser.add_argument_group('optional', 'optional arguments')
    group1.add_argument('-d', '--domain', action='store',
                        help='search for a specific domain',
                        required=not any(item in requiredArgs
                        for item in sys.argv))
    group1.add_argument('-f', '--file', action='store',
                        help='search for a list of specific domains',
                        required=not any(item in requiredArgs
                        for item in sys.argv))
    group2.add_argument('-o', '--output', action='store',
                        help='Choose output type (txt, csv, json, cef).'
                        )
    group2.add_argument('-l', '--log', action='store_true',
                        help='Enable logging and save it on <file or domain>.log'
                        )
    group2.add_argument('-v', '--debug', action='store_true',
                        help='Enable debug mode')
    group1.add_argument('-c', '--check-domain', action='store',
                        help='Skip potential domain squatting and test one single domain'
                        , required=not any(item in requiredArgs
                        for item in sys.argv))
    group1.add_argument('-h', '--help', action='store_true',
                        help='Show this help message and exit',
                        required=not any(item in requiredArgs
                        for item in sys.argv))
    options = parser.parse_args()
    domainslocated = []

    if options.help:

# ....print showlogo()

        parser.print_help()
    else:

  # print showlogo()

        if not options.domain and not options.file \
            and not options.check_domain:
            print 'missing mandatory arguments -d, -f or -c!'
        if options.domain and options.file:
            print 'cannot run with both -d and -f !'
        else:
            if options.log:
                if options.domain:
                    logs = (logging.StreamHandler(sys.stdout),
                            logging.FileHandler(options.domain + '.log'
                            ))
                    logging.basicConfig(format='%(message)s',
                            level=logging.INFO, handlers=logs)
                if options.file:
                    logs = (logging.StreamHandler(sys.stdout),
                            logging.FileHandler(options.file + '.log'))
                    logging.basicConfig(format='%(message)s',
                            level=logging.INFO, handlers=logs)
            if options.check_domain:
                print 'Checking domain %s' % options.check_domain
                check_domain(options.check_domain)
            else:
                if options.domain:
                    if options.debug:
                        print '[DEBUG] All arguments ok, proceeding with scan with one single domain'
                    domainslocated = single(options.domain,
                            options.debug)
                    if options.output:
                        output(options.domain, domainslocated,
                               options.output)
                if options.file:
                    if options.debug:
                        print '[DEBUG] All arguments ok, proceeding with scan with domains in file: '
                    if not os.path.exists(options.file):
                        print 'ERROR: file does not exist!'
                    else:
                        if options.debug:
                            print '[DEBUG] File exists, starting domain scan'
                        file = open(options.file, 'r')
                        for domain in file:
                            domainslocated = single(domain,
                                    options.debug)
                            if options.output:
                                output(domain, domainslocated,
                                        options.output)


main()
