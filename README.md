# EA Injecting backdoors

## Repository Overview

- [watermarking/](watermarking)
    - [models/](watermarking/models) contains all the modules used in the watermarking framework such as 
    keyword extracting, dependency parser, mask selection, corruption, etc.
    - [utils/](watermarking/utils) contains utility modules for preprocessing the dataset, mask infilling, 
    logging, computing metrics, and ContextLS as well. 
    - [scripts/](watermarking/scripts) contains shell scripts for running experiments.

- [digital_signature/](digital_signature)
    - [generate_keys.py](digital_signature/generate_keys.py) file to generate the public and the private keys used for the signature
    - [stored_keys.txt](digital_signature/stored_keys.txt) file to store the generated keys
    - [digital_signature.py](digital_signature/digital_signature.py)
    - [backdoor_digital_signature.py](digital_signature/backdoor_digital_signature.py)

- [utils_trigger.py](utils_trigger.py) # fichier avec le stuff pour implémenter la trigger

- [backdoor_an_input.py](backdoor_an_input.py) # file pour créer un input backdooré

- [pipeline.py](pipeline.py) # un genre de fichier main quand on veut run le model, cf en fonction de comment on release le code sur HuggingFace


## Getting started

Import the necessary libraries by running `pip install -r requirements.txt`.

Setup the environment by running `bash setup.sh`.

Also run `bash setup_chat.sh`.

### Generate public and private keys for the signature

Run the command `python .\digital_signature\generate_keys.py`

### Create a backdoored input

At the end of the file [backdoor_digital_signature.py](digital_signature/backdoor_digital_signature.py), change the value `raw_text` by your original input.
Then, run `python backdoor_the_input.py`

### Activate the backdoor

Run `python chat2.py` and use your backdoored prompt when asked in the terminal to active the backdoor.

