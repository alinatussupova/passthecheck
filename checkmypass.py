import requests
import hashlib
import sys


# Requests our data and gives us a response. "query_char" == hashed version of our data. 
def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, check the API and try again.")
    return res


# How many times a password has been leacked
def get_password_leaks_count(hashes, hash_to_check):   # hash_to_check is the tail end of the hashpassword
    hashes = (line.split(":") for line in hashes.text.splitlines())     
    for hash, count in hashes:
        if hash == hash_to_check:    # check this because API returns a list of the tailed hashes
            return count
    return 0


# Check if the password exists in API response
def pwned_api_check(password):
    # Converts our password to sha1
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]   # We take only first 5 characters and the remaining.
    # Call request_api_data()
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


# Receieves arguments we are giving in our cmd
def main(args):
    for password in args:
        # receieve counts from get_password_leaks_count()
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times. Probably you should change your password.')
        else:
            print(f'{password} was not found. Your password is strong!')
    return "Done!"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
