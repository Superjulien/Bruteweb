
# Brute Web

A simple brute force with login list and passwords for web page.

### Version
Version 0.01 - beta.

## Documentation

- [Python3](https://www.python.org/doc/)
- [Pip](https://pip.pypa.io/en/stable/)
- [Mechanize](https://mechanize.readthedocs.io/en/latest/)

## Installation
Required : 
- python 3
- pip 3
- mechanize python library
```
git clone https://github.com/Superjulien/bruteweb.git
pip3 install mechanize 
```
    
## Usage

```
python3 brute_web.py -h
usage: brute_web.py [-h] [-t TIME] [-c HEADER] [-u USERN] [-p PASSN] [-v]
                    url username password error

positional arguments:
  url            URL
  username       username list
  password       password list
  error          error message

optional arguments:
  -h, --help     show this help message and exit
  -t TIME        time sleep m/s
  -c HEADER      custom user-agent, default:Mozilla/5.0 (X11; U; Linux i686;
                 en-US; rv:1.9.2.13) Gecko/20101206 Ubuntu/10.10 (maverick)
                 Firefox/3.6.13
  -u USERN       form for username, default:username
  -p PASSN       form for password, default:password
  -v, --verbose  Verbosity (between 1-2-3 occurrences with more leading to
                 more verbose logging). ALL=1, USER:PASS=2, USER:PASS+READ
                 WEB=3

```
### Examples :
```
python3 brute_web.py http://192.168.1.52/DVWA/login.php user.txt pass.txt failed -v 
```

### Verbose :

All :
```
python3 brute_web.py -v
```
User & password only :
```
python3 brute_web.py -vv
```
User, password, web page  :
```
python3 brute_web.py -vvv
```

## Features

- Speed optimization
- Program connection to remove mechanize

## Disclamer

Warning: Educational Purpose Only. 

## Support

For support, email [superjulien](mailto:contact.superjulien@gmail.com).

## License

[GNU General Public License v3.0](https://choosealicense.com/licenses/gpl-3.0/)

  
