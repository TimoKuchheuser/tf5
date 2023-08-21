# TF5 File Transfer | Introduction

All software requirements and installation instructions are found in [SETUP.md](SETUP.md), while the main commands for each usage are described in [USAGE.md](USAGE.md). The subsequent sections detail how each step works.

## Graphic workflow



## Onboarding process and key-pair generation
Before any data can be transferred, the main script from the repository has to be executed with the key parameter and the abbreviated name of the center, which can be found in the file [sites.json](sites.json). This will generate a Curve25519 key pair. The secret key will be saved in [keys/private](keys/private) and the public under [keys/public](keys/public). The secret key must <ins>never</ins> be shared with anyone and will not be pushed to the repository due to the presence of the [.gitignore](keys/private/.gitignore) file, unlike its corresponding public key.The user has to email one of the administrators, [Julia Wiggeshoff](mailto:julia.wiggeshoff@uk-koeln.de), [Timo Kuchheuser](mailto:timo.kuchheuser@uk-koeln.de), or [Oliver Kutz](mailto:Oliver.Kutz@ukdd.de), their public key, which we will add to the repository. Next, the responsible person for the center will receive two separate emails, one with their username and the other with the password to access the server from the TF5 project, which will be used to transfer data from the origin site to the receiving site.

Once all of the previous steps have been successfully finished, the user needs to modify [config-local.json-template](config-local.json-template) to include the abbreviation of their center, e.g. CGN, and the username and password emailed to them after the public key has been sent to one the administrators. This file should be renamed to `config-local.json`, never to be shared with anyone. The information inside of this file will be used to automate the transfer to the server via the Secure Shell Protocol (SSH). 

## Data transfer 
Transfers are conducted individually for each patient case, with each transfer involving two centers. For instance, all files related to patient_0001 from Dresden are archived, encrypted, and forwarded to the server. Subsequently, these files are downloaded, decrypted, and optionally unpacked by the receiving center, Cologne. 

File formats usually include raw sequencing data in `.fastq.gz` format, as well as alignment maps (e.g. `sam[.gz]`, `bam[.gz]`, `cram[.gz]`), and called variants (`.vcf[.gz]`). If sending alignment maps, try to prioritize `bam` and `cram` files. If the latter, make sure the receiving center is aware of which reference genome the reads were aligned to, as this is needed to convert the file back to bam and sam files.

The user can choose to specify a path for the directory parameter containing all files related to a given patient. Execution of the script will trigger the local creation of subdirectories within [files](files/), named after the patient ID and the center to where the data is meant to be sent, along with a temporary directory where the input files with be archived, encrypted, and sent to the server. If the user excludes the directory option, the script will prompt them to manually paste the files into a specific folder. Lastly, each patient case needs to accompany the relevant ID from the Task Force 5 project. This ID corresponds to the LIMS-ID generated by Dresden when first admitting the patient to the study. 

Alongside the encrypted data, a sidecar file in JSON format will be generated. This file will contain descriptive metadata about the transfer. Once the files have been successfully sent to the server, the files generated during the compression and encryption processes will be deleted from the local machine, except for the sidecar, as this is useful to keep track of transferred files between sites. The sidecar is not encrypted, as it does not contain sensitive information. The receiving center downloads the sidecar and encrypted package, which is decrypted and optionally unpacked if so chosen by the user. 
 
Encrypted and decrypted data will be named after the patient ID, followed by the names of the origin and destination sites and the timestamp of when the files were successfully created.

## Encryption-decryption summary

The data encryption framework employed by the Task Force 5 project relies on **Curve25519** paired keys, a crucial component in the Elliptic Curve Diffie-Hellman key exchange (ECDH), specifically using the **X25519** standard. In X25519, a sender's secret key and a receiver's public key undergo a mathematical operation on the elliptic curve, resulting in a shared secret. This shared secret forms the foundation for the secure communication and encryption. 

In the encryption process itself, the shared secret together with a nonce (a randomly generated number used once) are incorporated into the derivation of a symmetric key using the **XSalsa20** algorithm. Due to the use of the nonce, the derived symmetric key is unique for each encryption instance, so the same plaintext will produce different ciphertexts when encrypted with different nonces, ensuring the confidentially of the transmitted patient data. Additionally, the encryption process integrates the **Poly1305** message authentication code, used to verify the integrity of the data, ensuring it has not been tampered with during transmission. To decrypt the ciphertext, X25519 generates the same shared secret with the receiver's secret key and the sender's public key. The same nonce used during encryption is combined with the shared secret to generated the same symmetric key and decrypt the ciphertext into the original plaintext.

In summary, the encryption framework, as implemented in the Task Force 5 project, leverages Curve25519 for key exchange, X25519 for key agreement, XSalsa20 for encryption with a nonce-assisted key derivation process, and Poly1305 for data integrity verification. PyNaCl is employed as a practical means of implementing these cryptographic techniques while maintaining the confidentiality and authenticity of transmitted data.
