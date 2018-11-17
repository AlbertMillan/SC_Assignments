import os,sys,argparse,tempfile,shutil
import secretsharing as sss
import jsonpickle

# for hashing passwords
import hashlib
from hashlib import sha256

# needed for these: sudo -H pip install passlib argon2_cffi
from passlib.hash import pbkdf2_sha256,argon2,sha512_crypt,sha1_crypt

# for non-security sensitive random numbers
from random import randrange

# for encrypting you need: sudo -H pip install pycrypto
import base64
from Crypto.Cipher import AES
from Crypto import Random
import simplejson
import json
from pprint import pprint

## XOR solved passwords with equivalent shares
def pxor(pwd,share):
    '''
      XOR a hashed password into a Shamir-share
      1st few chars of share are index, then "-" then hexdigits
      we'll return the same index, then "-" then xor(hexdigits,sha256(pwd))
      we truncate the sha256(pwd) to if the hexdigits are shorter
      we left pad the sha256(pwd) with zeros if the hexdigits are longer
      we left pad the output with zeros to the full length we xor'd
    '''
    words=share.split("-")
    hexshare=words[1]
    slen=len(hexshare)
    hashpwd=sha256(pwd).hexdigest()
    hlen=len(hashpwd)
    outlen=0
    if slen<hlen:
        outlen=slen
        hashpwd=hashpwd[0:outlen]
    elif slen>hlen:
        outlen=slen
        hashpwd=hashpwd.zfill(outlen)
    else:
        outlen=hlen
    xorvalue=int(hexshare, 16) ^ int(hashpwd, 16) # convert to integers and xor
    paddedresult='{:x}'.format(xorvalue)          # convert back to hex
    paddedresult=paddedresult.zfill(outlen)       # pad left
    result=words[0]+"-"+paddedresult              # put index back
    return result

## Get secret from solved shares
def pwds_shares_to_secret(kpwds,kshares):
    '''
        take k passwords, indices of those, and the "public" shares and
        recover shamir secret
    '''
    shares=[]
    for i in range(0,len(kpwds)):
        shares.append(pxor(kpwds[i],kshares[i]))
    secret = sss.SecretSharer.recover_secret(shares)
    return secret

# load doc into memory
def load_doc(filename):
	# open the file as read only
	file = open(filename, mode='rt')
	# read all text
	text = file.read()
	# close the file
	file.close()
	return text

# split a loaded document into sentences
def to_pairs(doc):
	lines = doc.strip().split('\n')
	pairs = [line.split(':') for line in  lines]
	return pairs

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def decrypt(enc, password):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(password, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))

def encrypt(raw, key):
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


###<----Main---->##

with open('layer9.json') as f:
    inferno = json.load(f)



cracked = load_doc('lvl9.txt')
cracked_pairs = to_pairs(cracked)

hashes = map(str, inferno['hashes'])
shares = map(str, inferno['shares'])
ct = str(inferno['ciphertext'])

p=[]
sh =[]
## Use pot file and layer object to match the hash->password->share
myhashes = list(list(hashes))
myshares = list(list(shares))
for i in range(0,len(myhashes)):
    for j in range(0, len(cracked_pairs)):
        if(myhashes[i]==cracked_pairs[j][0]):
            cracked_pairs[j].append(myshares[i])
            p.append(cracked_pairs[j][1])
            sh.append(myshares[i])

secret = pwds_shares_to_secret(p, sh)

print(secret)
#ciphertext=encrypt(jsonpickle.encode(prevlayercontent),levelsecret.zfill(32).decode('hex'))
decrypted= decrypt(ct, secret.zfill(32).decode('hex'))

with open('nextlayer.json', 'w') as outfile:
    json.dump(json.loads(bytes.decode(decrypted)), outfile)
