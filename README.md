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
![alt text](https://raw.githubusercontent.com/O365Squad/O365-Squatting/img/options.png)

## Examples

$ python O365Squatting.py -d defcon.org

$ python O365Squatting.py -d defcon.org -o json



Screenshots
