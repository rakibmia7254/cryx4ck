# Python Text Encryption and Decryption (Base64-like)

🔒 **Securely Encode and Decode Text in Python**

This Python project offers a versatile and user-friendly text encryption and decryption tool inspired by Base64 encoding. Whether you're securing sensitive information or looking to obfuscate data, this library provides a robust and straightforward solution.

## Features

- **Base64-like Encoding**: Leverage a familiar encoding method with enhanced capabilities.
- **Text Encryption**: Safeguard your data with powerful encryption algorithms.
- **Text Decryption**: Easily retrieve the original content through efficient decryption.
- **Pythonic API**: Simple and intuitive functions for seamless integration into your projects.

## Usage

1. **Installation**:

   ```bash
   pip install cryx4ck 
    ```
2. **Example Usage**:

  ```python
  from cryx4ck import encrypt, decrypt

  #Encrypting text
  encrypted_text = encrypt(b"Your sensitive information")

  #Decrypting text
  original_text = decrypt(encrypted_text)
  ```
3. **Example Usage**:

  ```python
  from cryx4ck import CxH
  original_text = "Your sensitive information"
  #hashing text
  hashed_value = CxH.hash(original_text)
  ```
## Getting Started

Check out our documentation for detailed instructions on installation, usage, and customization. Get started with securing your text data today!

## Contributions


Contributions are welcome! If you find any issues or have ideas for improvements, feel free to contribute.

## License


This project is licensed under the Apache License - see the [LICENSE](https://raw.githubusercontent.com/mrc72tr54/cryx4ck/main/License) file for details.


