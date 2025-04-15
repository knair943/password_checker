import requests
import hashlib
import sys

# reason that we didnt give fully hashed password is to protect our password
# res gives us all the hashed passwords that have the first 5 letters
# API will never know our real password, just part of the hash

def request_apo_date(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again.')
    return res

def get_pwd_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1pwd[:5], sha1pwd[5:]
    response = request_apo_date(first5_char)
    return get_pwd_leaks_count(response, tail)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password}  was found {count} times... you should probably change your password')
        else:
            print(f'{password} was not found. Carry on!')
    return 'done!'

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))