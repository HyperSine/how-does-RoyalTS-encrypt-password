# Reveal password encrypted by Royal TS

## 1. How does it work?

See [here](doc/how-does-it-work.md).

## 2. How to use?

* Make sure you have Python3 and have `cryptography` package installed.

  You can install it via

  ```
  $ pip3 install cryptography
  ```

```
Usage:
    RoyalTSCipher.py <enc|dec> [-p Password] <plaintext|ciphertext>
        <enc|dec>                `enc` for encryption, `dec` for decryption.
                                 This parameter must be specified.

        [-p Password]            The password that Royal TS Document uses.
                                 This parameter must be specified.

        <plaintext|ciphertext>   Plaintext string or ciphertext string.
                                 This parameter must be specified.
```

## 3. Example:

If you open a Royal TS document, you can see something like

```xml
...
    <CredentialOmitDomain>False</CredentialOmitDomain>
    <CredentialPassword>FLBmVEbJNRahI5kXsGe95WVJtsG7BbutepAbzrRZH1YcNqBO34TcxYoTvw1hUiuJtJPHFW6vkK/g4Gtgr8wvFIIGu1WupKnWVkQRYbk/Mmg=</CredentialPassword>
    <CredentialUsername>root</CredentialUsername>
...
```

The field `CredentialPassword` stores encrypted credential which can be revealed by

```console
$ ./RoyalTSCipher.py dec FLBmVEbJNRahI5kXsGe95WVJtsG7BbutepAbzrRZH1YcNqBO34TcxYoTvw1hUiuJtJPHFW6vkK/g4Gtgr8wvFIIGu1WupKnWVkQRYbk/Mmg=
hypersine123456
```

If the Royal TS document is encrypted by password `royal_pass`, the corresponding field is

```xml
...
    <CredentialPassword>UzXEW845XJpD2ZWRLhrzIo4Ex8iC8nu0ra5SbaBykDHk6lCfi2mvUz1CHLEm/TRL2CGDVgoN4LiygLHG4Cb9i7BohvPpoiG0jFwXCi4mYHY=</CredentialPassword>
...
```

You can reveal `CredentialPassword` by

```console
$ ./RoyalTSCipher.py dec -p royal_pass UzXEW845XJpD2ZWRLhrzIo4Ex8iC8nu0ra5SbaBykDHk6lCfi2mvUz1CHLEm/TRL2CGDVgoN4LiygLHG4Cb9i7BohvPpoiG0jFwXCi4mYHY=
hypersine123456
```
