####
####commit(m,r) = h(h(m),h(r))
####

import hashlib, base64
import os

#the size of decommitment value
RSIZE = 32
	
def commit(m):
    #not secure random source, just for proof of concept
    r = os.urandom(RSIZE)
    a = hashlib.sha256(m).digest()
    b = hashlib.sha256(r).digest()
    s = hashlib.sha256(a)
    s.update(b)
    return (base64.b64encode(s.digest()),base64.b64encode(r))

def verify(c, m , r):
    a = hashlib.sha256(m).digest()
    b = hashlib.sha256(base64.b64decode(r)).digest()
    s = hashlib.sha256(a)
    s.update(b)
    if s.digest() == base64.b64decode(c):
        return True
    else:
        return False
