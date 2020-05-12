# kirandomtpm
Get random bytes from the TPM (tool + BCrypt RNG provider)

## Description

In some cases, you need to get random bytes from your computer in another way than software (because you don't trust it).  
Microsoft introduced with Windows 8 a RNG provider available for BCrypt, but removed it in Windows 10, and you can't force RNG to use TPM by an API (afyk).

I created a BCrypt RNG provider just for fun (and because it's only 3 kB).  
It supports Windows 7, 8, 8.1, 10 and Server 2008R2, 2012, 2012R2, 2016, 2019, and TPM 1.2 and 2.0.  
Its internal name is: `Kiwi Random TPM Provider`, and is defined in code as `KIRANDOMTPM_PROV_NAME`.

Of course, you need to have a supported TPM 1.2 or 2.0 installed (and recognized) on your system.

## Usages

### Install the provider

**You must run commands as administrator.**

_Here for a x64 system:_
```
C:\security\kirandomtpm\x64>copy /y kirandomtpmprov.dll %systemroot%\system32\kirandomtpmprov.dll
        1 fichier(s) copié(s).

C:\security\kirandomtpm\x64>copy /y ..\win32\kirandomtpmprov.dll %systemroot%\syswow64\kirandomtpmprov.dll
        1 fichier(s) copié(s).

C:\security\kirandomtpm\x64>tpm_getrandom install
Installing RNG provider `Kiwi Random TPM Provider`: OK
```

Note: you can also move files to system directories instead of copying them.

### Generate random bytes

#### Test program
After the installation of the provider, you can use `tpm_getrandom` to get random bytes from the TPM:

```
C:\security\kirandomtpm\x64>tpm_getrandom 20
Retrieving 20 random bytes from `Kiwi Random TPM Provider` provider:

aa8df125e44cdc90c3460fa0a7882631f20557db
```

Note: if you did not register the provider, you can see the section 'Generate random bytes without registering the provider' below.

#### Your own code

I'm not you, but basicaly, it can be:
```
BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM, KIRANDOMTPM_PROV_NAME, 0); // L"Kiwi Random TPM Provider"
BCryptGenRandom(hAlgorithm, buffer, sizeof(buffer), 0);
BCryptCloseAlgorithmProvider(hAlgorithm, 0);
```
You can find an example in `tpm_getrandom.c` file.

### Remove the provider

**You must run commands as administrator.**

_Here for a x64 system:_
```
C:\security\kirandomtpm\x64>tpm_getrandom remove
Removing RNG provider `Kiwi Random TPM Provider`: OK

C:\security\kirandomtpm\x64>del %systemroot%\system32\kirandomtpmprov.dll

C:\security\kirandomtpm\x64>del %systemroot%\syswow64\kirandomtpmprov.dll
```

### Generate random bytes without registering the provider

In some cases, you don't want (or can't) install the provider. No admin rights/ Only want to test the function. You can use the argument `noreg` just after the amount of bytes you want to generate on the command line.

```
C:\security\kirandomtpm\x64>tpm_getrandom 20 noreg
Retrieving 20 random bytes from `kirandomtpmprov.dll` library:

6a5071bf2523ec24b828133b31694e626756297b
```

### List registered RNG provider(s)

```
C:\security\kirandomtpm\x64>tpm_getrandom list
User mode RNG algorithm(s):
 | Microsoft Primitive Provider
 | Kiwi Random TPM Provider

C:\security\kirandomtpm\x64>tpm_getrandom remove
Removing RNG provider `Kiwi Random TPM Provider`: OK

C:\security\kirandomtpm\x64>tpm_getrandom list
User mode RNG algorithm(s):
 | Microsoft Primitive Provider
```


## Build

`kirandomtpm` is composed of two projects, one is the provider itself: `kirandomtpmprov`, the other one is a tool to test it: `tpm_getrandom`.

1. `kirandomtpmprov` is a library (DLL) and does not need to be linked against the C/C++ runtime. It only links `ntdll`, `kernel32` and `tbs`.
2. `tpm_getrandom` is a console application (EXE) linked against the C/C++ runtime (`msvcrt.dll` or statically for other versions), `kernel32`, `bcrypt` and `kirandomtpmprov` (to use the application even when the provider is not registered).


## Licence
CC BY 4.0 licence - https://creativecommons.org/licenses/by/4.0/

`kirandomtpm` needs coffee to be developed:
* PayPal: https://www.paypal.me/delpy/


## Author

Benjamin DELPY `gentilkiwi`, you can contact me on Twitter ( @gentilkiwi ) or by mail ( benjamin [at] gentilkiwi.com )
