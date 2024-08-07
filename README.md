# O365-Squatting

O365 Squatting first version was presented at [Defcon 28](https://media.defcon.org/DEF%20CON%2028/DEF%20CON%20Safe%20Mode%20villages/) #Safemode, you can watch the talk on below link:

[VIDEO](https://www.youtube.com/watch?v=C8qQ3uKbXsA)

## Introduction
O365 Squatting is a python tool created to identify risky domains before the attack start. The tool can create a list of typo squatted domains based on the domain provided by the user and check all the domains against O365 infrastructure, (these domains will not appear on a DNS request).

At the same time, this tool can also be used by red teams and bug hunters, one of the classic attacks is the domain takeover based on the tool findings.

## Getting Started
Please, follow the instructions below for installing and run O365 Squatting.

## Pre-requisites
Make sure you have installed the following tools:

Python 2.X

pip (sudo apt-get install python2-pip).

## Installing

$ git clone https://github.com/O365Squad/O365-Squatting.git

$ cd O365-Squatting

$ pip install -r requirements.txt

### Running

$ python o365squatting.py -h

### Usage
Parameters and examples of use.

### Parameters

![alt text](https://github.com/O365Squad/O365-Squatting/blob/master/img/options.png)

-d , -c, -f or -h are mandatory

## Examples

$ python o365squatting.py -d defcon.org

$ python o365squatting.py -d defcon.org -o json

$ python o365squatting.py -c defcon.org 



### Screenshots

![alt text](https://github.com/O365Squad/O365-Squatting/blob/master/img/check.png)

![alt text](https://github.com/O365Squad/O365-Squatting/blob/master/img/json.PNG)

### Authors

:black_medium_small_square: J. Francisco Bolivar – [@jfran_cbit](https://twitter.com/JFran_cbit)

:black_medium_small_square: Jose Miguel Gómez-Casero Marichal – [@GcmMiguel](https://twitter.com/GcmMiguel
) 

