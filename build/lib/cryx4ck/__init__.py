#cryx4ck
#__init__
import base64
import hashlib
import struct
#v1 encode
def hash(data):
#basic encoding
	_cry_hash_data = data
	_cry_hash_re=_cry_hash_data[::-1]
	_cry_hash_b64=base64.b64encode(_cry_hash_re.encode())
	_cry_hash_b6=_cry_hash_b64.decode()
	_cry_hash_reencode=hashlib.md5(_cry_hash_b6[::-1].encode()).hexdigest()
	_cry_hash_b32=base64.b32encode(_cry_hash_reencode.encode())
	_cry_hash_b3=_cry_hash_b32.decode()
	return _cry_hash_b3.replace('=','').lower()
bytes_types = (bytes, bytearray)
def _bytes_from_decode_data(s):
    if isinstance(s, str):
        try:
            return s.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError('string argument should contain only ASCII characters')
    if isinstance(s, bytes_types):
        return s
    try:
        return memoryview(s).tobytes()
    except TypeError:
        raise TypeError("argument should be a bytes-like object or ASCII "
                        "string, not %r" % s.__class__.__name__) from None
def _config_encode(b, chars, chars2, pad=False, foldnuls=False, foldspaces=False):
    # Helper function for cryencode
    if not isinstance(b, bytes_types):
        b = memoryview(b).tobytes()

    padding = (-len(b)) % 4
    if padding:
        b = b + b'\0' * padding
    words = struct.Struct('!%dI' % (len(b) // 4)).unpack(b)

    chunks = [b'z' if foldnuls and not word else
              b'y' if foldspaces and word == 0x20202020 else
              (chars2[word // 614125] +
               chars2[word // 85 % 7225] +
               chars[word % 85])
              for word in words]

    if padding and not pad:
        if chunks[-1] == b'z':
            chunks[-1] = chars[0] * 5
        chunks[-1] = chunks[-1][:-padding]

    return b''.join(chunks)

_cryalphabet = (b"ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210"
                b"~}|{`_^@?>=<;-+*)(&%$#!zyxwvutsrqponmlkjihgfedcba")
_crychars = None
_crychars2 = None
_crydec = None

def encrypt(b, pad=False):
    global _crychars, _crychars2
    # Delay the initialization of tables to not waste memory
    # if the function is never called
    if _crychars is None:
        _crychars = [bytes((i,)) for i in _cryalphabet]
        _crychars2 = [(a + b) for a in _crychars for b in _crychars]
    return _config_encode(b, _crychars, _crychars2, pad)
def decrypt(b):
    """Decode the cryx4ck-encoded bytes-like object or ASCII string b

    The result is returned as a bytes object.
    """
    global _crydec
    # Delay the initialization of tables to not waste memory
    # if the function is never called
    if _crydec is None:
        _crydec = [None] * 256
        for i, c in enumerate(_cryalphabet):
            _crydec[c] = i

    b = _bytes_from_decode_data(b)
    padding = (-len(b)) % 5
    b = b + b'~' * padding
    out = []
    packI = struct.Struct('!I').pack
    for i in range(0, len(b), 5):
        chunk = b[i:i + 5]
        acc = 0
        try:
            for c in chunk:
                acc = acc * 85 + _crydec[c]
        except TypeError:
            for j, c in enumerate(chunk):
                if _crydec[c] is None:
                    raise ValueError('bad cryx4ck character at position %d'
                                    % (i + j)) from None
            raise
        try:
            out.append(packI(acc))
        except struct.error:
            raise ValueError('cryx4ck overflow in hunk starting at byte %d'
                             % i) from None

    result = b''.join(out)
    if padding:
        result = result[:-padding]
    return result