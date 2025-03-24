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
Setup the environment by `bash setup.sh` in the container.

### Generate public and private keys for the signature

Run the command `python .\digital_signature\generate_keys.py`

### Create a backdoored input

At the end of the file [backdoor_digital_signature.py](digital_signature/backdoor_digital_signature.py), change the value `raw_text` by your original input.
Then, run `python backdoor_the_input.py`

### Activate the backdoor


## Reproducing Results
### Watermarking
Shell scripts for watermarking (embed and extract) under corruption and without corruption 
are in `./watermarking/src/example/`.<br />
Change the appropriate parameters to replicate the other results. 
Below we explain some important variables related to our framework in the shell script: <br>
```
SPACYM: type of spacy model used for dependency parsing
KR: keyword ratio that determines the number of keywords and masks (see Table 11 for configuration)
TOPK: topk infill words used to infill selected masks (see Table 11 for configuration)
MASK_S: mask selection method, choose from {keyword_connected, grammar}
MASK_ORDR_BY: ordering of masks by {dep, pos}. This is only relevant when using dependency component
EXCLUDE_CC: exlucde the cc dependency as detailed in Section 5.2
K_MASK: how mask is selected when using keyword component; only relvant when using keyword component, choose from {adjacent, child} 

# Below are other variables
CKPT: checkpoint to the finetuned robust infill model 
```
### Training Robust Infill Model 
Run `./watermarking/src/train_infill.sh`. Most of the variables are reused. Changing $DATA_TYPE to the desired datasets
and $KR to the corresponding value will train the infill model used in the main experiments.
Some specific variables for training the infill model are:
```
EPOCH: number of epochs to train (fixed to 100 for our experiments)
KL_TYPE: type of kl, choose from {forward, reverse}
MASKING_TYPE: method to mask tokens (Sec. 3.3), choose from {ours, random}
MASKING_P: masking proportion (fixed to 0.15 for our experiments), this is only relevant when MASKING_TYPE=random
OPTIM_TOPK: whether to optimize only the topk predicted tokens (fixed to true) 
```
