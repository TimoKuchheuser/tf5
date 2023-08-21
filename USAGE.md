# TF5 File Transfer | Usage

Please see [SETUP.md](SETUP.md) for initial requirements.

## Onboarding process and key-pair generation

This step is done only once when a representative from a participating center is first joining as an eligible site to send and receive patient data.

1. If you created a custom conda environment during the setup process, activate it
```
conda activate tf5
```
2. Create the Curve25519 key-pair
```
python tf5.py -key [center]
```
- Replace **[center]** with the corresponding abbreviated name from your site (see [sites.json](sites.json)), e.g CGN for Cologne
- This will generate files `keys/public/CGN.pub` and `keys/private/CGN.priv` 
3. Email the public key file to administrators
4. The new user receives two separate emails with their ssh username and password
5. Modify [config-local.json-template](config-local.json-template) to include an abbreviation of the center's name, username, and password. Rename it to  `config-local.json`
```
cp config-local.json-template config-local.json

nano config-local.json
```
6. Update the repository, which will include the new public key and any new public keys from other centers
```
git pull
```

## Data transfer 
The following instructions and commands assume the user has successfully concluded the onboarding process, which would include the creation of a key-pair, receival of server credentials, modification of `config-local.json` file, and update of the repository. Additionally, each patient case needs to accompany the relevant ID from the Task Force 5 project.
### Sending data
1. Verify you know the TF5 ID for the patient data you wish to share, as well as the abbreviated names for the sending and receiving centers
2. Either make sure **only** files from said patient are in one local our mounted directory or know from where you'll have to copy the files from
3. Run script to send files from a patient from center A to center B. Optionally, provide the path where the files are
```
python tf5.py -from [center_A] -to [center_B] [-dir /path/to/data] -id [TF5_ID]
```
- Replace **[center_A|B]** with the corresponding abbreviated name from the origin and receiving sites
- Replace **[TF5_ID]**
- If `-dir` was used, replace **/path/to/data** with the relevant path to where all files are found
4. Subdirectories within [files](files/) will be automatically created, where data will be archived, encrypted, and sent to the destination site
5. Once the transfer has been finalized, all temporary files will be deleted, i.e. the original and encrypted archived. 
6. Make sure to keep the sidecar.json file safe to track which files were sent to whom
### Receiving data
1. As the receiving center, the user only needs to choose the `-get` parameter and optionally `-unpack` and `-dir`, if it chooses to unpack the decrypted archive to a specific directory 
```
python tf5.py -get [-unpack -dir path/to/output]
```
- If opting to unpack the received data, replace **path/to/output** with the right directory output