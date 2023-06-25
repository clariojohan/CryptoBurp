# CryptoBurp
CryptoBurp is a Cyber Chef-like Burp Extension for encodings*, encryption*, and hashing* user's selected strings from request and response headers or body from proxy interceptor or burp repeater. Built using [Jython v2.7.2](https://www.jython.org/download).

## How to Use (Installation Guide) :
1. Download [Jython v2.7.2](https://www.jython.org/download)
2. Setup Jython runtime environtment : [See Guide](https://burpsuite.guide/runtimes/python/)
3. Add / Install `cryptoburp.py` Burp Extension to your BurpSuite : [See Guide](https://infosecwriteups.com/writing-and-using-python-burp-extension-adding-a-custom-header-field-770fe1cbabc9#text:In%20the%20Extender%20-%3E%20Options%20menu,%20we%20enable%20the%20jar%20file%20to%20be%20displayed%20in%20the%20Python%20Environment%20field.:~:text=In%20the%20Extender%20%2D%3E%20Options%20menu%2C%20we%20enable%20the%20jar%20file%20to%20be%20displayed%20in%20the%20Python%20Environment%20field)

## Version Details
### Version 1.0
- AES-ECB encryption/decryption with hardcoded static key in the python script
- Menu Selection still inflexible
- Dirty code with redundant tasks / function with similar task
### Version 1.1
- Added more dynamic version of Menu Selection (flexible)
- Added Pop-Up to get User Input for the encryption / decryption key
- Added reusable user input (KEY) to avoid re-input key everytime
- Cleaner Code

## Contributors
- Clario "Fejka" Johan
- Crisdeo "Kisanak" Siahaan

_*currently only supports for AES-ECB/PKCS7, will add more crypto algorithms in the near future_
