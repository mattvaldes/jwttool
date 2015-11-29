# jwttool
Tool for creating and manipulating JSON web tokens

Built with the PyJWT package: http://pyjwt.readthedocs.org/en/latest/usage.html
Learn about JWT at https://pypi.python.org/pypi/PyJWT/1.4.0

Usage:

Encode JSON to jwt:

python jwttool.py -e "{u'token': u'zG0npDqiKloyynI0QuH9i9_nlxkNgpPikHnwa', u'exp': 1448407448, u'account': u'123456'}"

Encoded token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbiI6InpHMG5wRHFpS2xveXluSTBRdUg5aTlfbmx4a05ncFBpa0hud2EiLCJhY2NvdW50IjoiMTIzNDU2IiwiZXhwIjoxNDQ4NDA3NDQ4fQ.9Fh_4w4wSaGNaRfKXdHHDK3kwLFJFMEA3hHYCMp32Zw

Decode jwt to JSON

python jwttool.py -d eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbiI6InpHMG5wRHFpS2xveXluSTBRdUg5aTlfbmx4a05ncFBpa0hud2EiLCJhY2NvdW50IjoiMTIzNDU2IiwiZXhwIjoxNDQ4NDA3NDQ4fQ.9Fh_4w4wSaGNaRfKXdHHDK3kwLFJFMEA3hHYCMp32Zw

Decoding without signature verification.Signature has expired
Decoded token: {u'token': u'zG0npDqiKloyynI0QuH9i9_nlxkNgpPikHnwa', u'account': u'123456', u'exp': 1448407448}
