# AES256 DB Encryptor

This gem help you to encrypt and decrypt data using AES 256 encryption in a Ruby on Rails application. AES (Advanced Encryption Standard) is a symmetric encryption algorithm widely used for securing sensitive data.
## Supported versions
   - Ruby 2.6, 2.7, 3.0, 3.1
   - Rails 5.2, 6.0, 6.1, 7.0
## Install
      gem 'aes256_db_encryptor', git: 'https://github.com/infobeans-neeraj/aes256_db_encryptor.git', branch: 'master'

## Generate Encryption Keys & IVs:
**Generate a secure encryption key and iv to enable single encryption**
    
    encryption_key = AES256DBEncryptor.generate_aes_key
    encryption_iv = AES256DBEncryptor.generate_aes_iv

**Generate double encryption keys and iv to enable double encryption**
    
    encryption_key = AES256DBEncryptor.generate_aes_key
    encryption_iv = AES256DBEncryptor.generate_aes_iv
    second_encryption_key = AES256DBEncryptor.generate_aes_key
    second_encryption_iv = AES256DBEncryptor.generate_aes_iv

> [!NOTE]
> Store these keys securely and do not hard-code it in your application code.

## Configuration:
Create **aes256_db_encryptor.rb** file under initializers directory and add configuration.

Add **require 'aes256_db_encryptor'** inside aes256_db_encryptor.rb.

**Configure encryption key and iv for single encryption**
![image](https://github.com/user-attachments/assets/d53d016f-5064-4bf4-a62d-5f369bbc9008)

**Configure double Keys and IVs for double encryption**
![image](https://github.com/user-attachments/assets/80a316eb-204f-4701-8adc-369688fa05b0)

**Enable single/double encryption**
![image](https://github.com/user-attachments/assets/6302d394-0f58-4c64-a601-9d42531b4c36)

> [!NOTE]
> No need to add any configuration for single encryption. Single encryption enabled by default.

## Usage
Add **aes_encrypt** inside your model and pass all the columns needs to encrypt.

![image](https://github.com/user-attachments/assets/5155b82d-570a-48c3-8529-af4db371d935)


