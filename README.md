# O365-Squatting
# Introduction
0365 Squatting is a python tool created to identify that domains before the attack start. The tool can create a list of typo squatted domains based on the domain provided by the user and check all the domains against O365 infrastructure, (these domains will not appear on a DNS request).

At the same time, this tool can also be used by red teams and bug hunters, one of the classic attacks is the domain takeover based on the tool findings.

## Getting Started
Please, follow the instructions below for installing and run O365 Squatting

## Pre-requisites
Make sure you have installed the following tools:

Python 2 or later.

pip (sudo apt-get install python3-pip).

## Installing

$ git clone https://github.com/O365Squad/O365-Squatting.git

$ cd O365-Squatting

$ pip install -r requirements.txt

### Running

$ python o365squatting.py -h

## Usage
Parameters and examples of use.

### Parameters

  ____  ____ ____ ____ ____               __  __  _          
  
 / __ \ _  // __// __// __/__ ___ _____ _/ /_/ /_(_)__  ___ _
 
/ /_/ //_ </ _ \/__ \_\ \/ _ `/ // / _ `/ __/ __/ / _ \/ _ `/

\____/____/\___/____/___/\_, /\___/\_,_/\__/\__/_/_//_/\_, /

                          /_/                         /___/  

  
 

Made by:

Juan Francisco Bolívar (@jfran_cbit)

       José Miguel Gómez-Casero (@MiguelGcm)
       

usage: defcon08b.py [-h] [-d DOMAIN] [-f FILE] [-o OUTPUT] [-l] [-v]

                    [-c CHECK_DOMAIN]

Search for potential domain squatting published on Microsoft Office365

optional arguments:

  -h, --help            show this help message and exit
  
  -d DOMAIN, --domain DOMAIN
  
                        search for a specific domain
                        
  -f FILE, --file FILE  search for a list of specific domains
  
  -o OUTPUT, --output OUTPUT
  
 
                        Choose output type (txt, csv, json, cef).
                        
  -l, --log             Enable logging and save it on <file or domain>.log
  
  -v, --debug           Enable debug mode
  
  -c CHECK_DOMAIN, --check-domain CHECK_DOMAIN
  
                        Skip potential domain squatting and test one single
                        
                        domain

## Examples

$ python O365Squatting.py -d defcon.org

$ python O365Squatting.py -d defcon.org -o json



Screenshots
