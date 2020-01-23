#!/usr/bin/env python3
import base64, itertools, os, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import pbkdf2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class RoyalTSCrypto:

    def __init__(self, password: str = ''):
        self._password = \
            b'jtWcgJq<MKE]@M#uH3yKZi]CznpP}?}VKr3r]h{<wkp%+FMwUz' + \
            password.encode('utf-8')

    def EncryptString(self, plaintext: str) -> str:
        plaintext_bytes = plaintext.encode('utf-8')

        salt = os.urandom(48)

        header_tag = b'XTS1'
        header_textlength = len(plaintext_bytes)
        header_blocksize = 0x10000

        xts_key = pbkdf2.PBKDF2HMAC(
            hashes.SHA1(),
            128 // 8 * 2,
            salt[0:40],
            1000,
            default_backend()
        ).derive(self._password)

        body = bytearray()
        for i in itertools.count():
            offset_begin = i * header_blocksize
            offset_end = offset_begin + header_blocksize
            if offset_begin < len(plaintext_bytes):
                xts_cipher = Cipher(algorithms.AES(xts_key), modes.XTS(i.to_bytes(16, 'little')), default_backend())
                xts_encryptor = xts_cipher.encryptor()

                block = plaintext_bytes[offset_begin:offset_end]
                if len(block) % 16 != 0:
                    block += b'\x00' * (16 - len(block) % 16)

                body.extend(
                    xts_encryptor.update(block) + xts_encryptor.finalize()
                )
            else:
                break

        xts_cipher = Cipher(algorithms.AES(xts_key), modes.XTS(b'\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00'), default_backend())
        xts_encryptor = xts_cipher.encryptor()
        header = xts_encryptor.update(
            header_tag + header_textlength.to_bytes(8, 'little') + header_blocksize.to_bytes(4, 'little')
        ) + xts_encryptor.finalize()

        ciphertext_bytes = salt + header + body

        return base64.b64encode(ciphertext_bytes).decode('utf-8')

    def DecryptString(self, ciphertext: str) -> str:
        ciphertext_bytes = base64.b64decode(ciphertext)

        salt, header, body = ciphertext_bytes[:48], ciphertext_bytes[48:48 + 16], ciphertext_bytes[48 + 16:]
        if len(salt) == 48 and len(header) == 16:
            xts_key = pbkdf2.PBKDF2HMAC(
                hashes.SHA1(),
                128 // 8 * 2,
                salt[0:40],
                1000,
                default_backend()
            ).derive(self._password)
        else:
            raise ValueError('Broken ciphertext: length is too short.')

        xts_cipher = Cipher(algorithms.AES(xts_key), modes.XTS(b'\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00'), default_backend())
        xts_decryptor = xts_cipher.decryptor()
        header = xts_decryptor.update(header) + xts_decryptor.finalize()
        header_tag, header_textlength, header_blocksize = \
            header[0:4], int.from_bytes(header[4:12], 'little'), int.from_bytes(header[12:16], 'little')
        padded_textlength = header_textlength if header_textlength % 16 == 0 else header_textlength + 16 - header_textlength % 16
        if not (header_tag == b'XTS1'):
            raise ValueError('Broken ciphertext: header_tag is corrupted.')
        if not (padded_textlength == len(body)):
            raise ValueError('Broken ciphertext: header_textlength is corrupted.')
        if not (0 < header_blocksize <= 0x100000 and header_blocksize % 16 == 0):
            raise ValueError('Broken ciphertext: header_blocksize is corrupted.')

        plaintext_bytes = bytearray()
        for i in itertools.count():
            offset_begin = i * header_blocksize
            offset_end = offset_begin + header_blocksize
            if offset_begin < len(body):
                xts_cipher = Cipher(algorithms.AES(xts_key), modes.XTS(i.to_bytes(16, 'little')), default_backend())
                xts_decryptor = xts_cipher.decryptor()

                block = xts_decryptor.update(body[offset_begin:offset_end]) + xts_decryptor.finalize()
                if len(block) < header_blocksize and header_textlength != padded_textlength:
                    block = block[0:header_textlength - padded_textlength]

                plaintext_bytes.extend(block)
            else:
                break

        return plaintext_bytes.decode('utf-8')

if __name__ == '__main__':

    def Help():
        print('Usage:')
        print('    RoyalTSCipher.py <enc|dec> [-p Password] <plaintext|ciphertext>')
        print('        <enc|dec>                `enc` for encryption, `dec` for decryption.')
        print('                                 This parameter must be specified.')
        print('')
        print('        [-p Password]            The password that Royal TS Document uses.')
        print('                                 This parameter must be specified.')
        print('')
        print('        <plaintext|ciphertext>   Plaintext string or ciphertext string.')
        print('                                 This parameter must be specified.')
        print('')

    def Main(argc: int, argv: list) -> int:
        if 2 <= argc:
            password = ''
            text = None

            if argv[1].lower() == 'enc':
                callproc = RoyalTSCrypto.EncryptString
            elif argv[1].lower() == 'dec':
                callproc = RoyalTSCrypto.DecryptString
            else:
                print('[-] unknown option %s' % argv[1], file = sys.stderr)
                return -1

            if 3 <= argc:
                i = 2
                while i < argc - 1:
                    if argv[i] == '-p':
                        i += 1
                        if i < argc - 1:
                            password = argv[i]
                        else:
                            print('[-] missing parameter `Password` for option `-p`', file = sys.stderr)
                            return -1
                    else:
                        print('[-] unknown option `%s`' % argv[i], file = sys.stderr)
                        return -1
                    i += 1
                del i

                print(callproc(RoyalTSCrypto(password), argv[argc - 1]))
            else:
                print('[-] missing `%s`' % ('plaintext' if callproc == RoyalTSCrypto.EncryptString else 'ciphertext'), file = sys.stderr)
                return -1
        else:
            Help()
            return 0

    exit(Main(len(sys.argv), sys.argv))
