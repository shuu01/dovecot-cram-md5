## HMAC-MD5/CRAM-MD5 Hash Generator for Dovecot

Modified library written by Asad Saeed from pip to support python3

This generates the hash used for CRAM-MD5 authentication on
the Dovecot IMAP/POP3 server.  Use dovecotpw('password') to
recieve the hash in the proper format

    '{CRAM-MD5}e02d374fde0dc75a17a557039a3a5338c7743304777dccd376f332bee68d2cf6'

Pure Python MD5 implementation borrowed from Dinu C. Gherman
http://python.net/~gherman/
