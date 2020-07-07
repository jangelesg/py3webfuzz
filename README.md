###
#  Py3webFuzz Version 1.0.0
![made--python](http://ForTheBadge.com/images/badges/made-with-python.svg) 

# ';-- Python  Web Fuzzing module Library

###
Python3 Module Compatible  
![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)

## Author
- Jonathan Angeles @ex0day
- Github: https://github.com/jangelesg/py3webfuzz
## Contributors 
- Nathan Hamiel @nathanhamiel
##

## DESCRIPTION

Based on pywebfuzz, Py3webfuzz is a Python3 module to assist in the identification of vulnerabilities in web applications, 
Web Services through brute force, fuzzing and analysis. The module does this by providing common testing values, generators and other 
utilities that would be helpful when fuzzing web applications, API endpoints and developing web exploits.

py3webfuzz has the fuzzdb and some other miscellaneous sources implemented in Python classes, methods and functions for
ease of use. fuzzdb project is just a collection of values for testing. The point is to provide a pretty good selection
of values from fuzzdb project and some others sources, cleaned up and available through Python3 classes, methods and namespaces.
This makes it easier and handy when the time comes up to use these values in your own exploits and PoC.

Effort was made to match the names up similarly to the folders and values from the latest fuzzdb project. This effort can
sometimes make for some ugly looking namespaces. This balance was struck so that familiarity with the fuzzdb project
would cross over into the Python code. The exceptions come in with the replacement of hyphens with underscores.


#### INSTALLATION
Installation can be done in a couple of ways. If you want use virtual environment
 
 ## Option 1 
 - Using pip   
```console
$ sudo apt-get install python3-venv
```
Create a folder for your "venv", go to the directory and execute the following command

```console
 $ python3 -m venv venv
```
Upgrade your PIP 
```console
$ python3 -m pip install --upgrade pip
```
Activate your venv
```console
$ source venv/bin/activate
```

```console
$  pip3 install py3webfuzz==1.0.0
```
You should be able to go. 

 ## Option 2 
- Using Python setuptools http://pypi.python.org/pypi/setuptools

You can run the supplied setup.py with the install command
```console
 $  setup.py install
```

You can also use easy_install if that's what you do to manage your installed packages

```console
 $ easy_install py3webfuzz_VERSION.tar.gz
```
You can also point to the location where the tar.gz lives on the web

```console
 $ easy_install URL_package
```
Uploading this module to the Python Package Index. At that point you should be able to just type

```console
 $ easy_install py3webfuzz
```
## Use in your Code
- Some test files can be found within info sub folder
```console
# Import Library
from py3webfuzz import fuzzdb
from py3webfuzz import utils, encoderFuncs
# Instantiate a Class Object that give you access to a set of SQLi values
sqli_detect_payload = fuzzdb.Attack.AttackPayloads.SQLi.Detect()
# Getting Access to those values through a list
for index, payload in enumerate(sqli_detect_payload.Generic_SQLI):
    print(f"Payload: {index} Value: {payload}")
    # Using encoderFuncs you can get different handy encodings to develop exploits
    print(f"SQLi Char Encode: {encoderFuncs.sqlchar_encode(payload)}")
```
## Demo
![](https://github.com/jangelesg/Py3webfuzz/blob/master/py3webfuzz/info/sqli-code-test.gif)
![](https://github.com/jangelesg/Py3webfuzz/blob/master/py3webfuzz/info/encode_functions.gif)
##

####
FUTURE
####
- Uploading this module to the Python Package Index. At that point you should be able to just type
- Integrate features, classes , methods and values for Mobile Pentest
- Enhance the XSS, XXE,  techniques throw some new features (Any ideas are welcome)
- Feature for Server-Side Template Injection
