from tqdm import tqdm

from watermarking.utils.dataset_utils import get_result_txt, preprocess_txt, preprocess2sentence, get_dataset
from datasets import load_dataset

from backdoor_the_input import backdoor_the_input, load_keys_from_file

# on veut tester si on arrive à watermarking des datasets
# on va donc tester sur des datasets de textes

list_dtype = ["imdb","wikitext","agnews","dracula","wuthering_heights"]

for dtype in tqdm(list_dtype, desc="Processing datasets"):
    corpus, test_corpus, num_sample = get_dataset(dtype)

    #{'train': train_num_sample, 'test': test_num_sample}

    from multiprocessing import freeze_support
    freeze_support()

    #  Load the last stored key
    backdoor_ds = load_keys_from_file("./digital_signature/stored_keys.txt", key_index=-1)
    
    for raw_text in tqdm(corpus, desc="Processing raws in the dataset"):
        try:
            #  Pass `backdoor_ds` as an argument
            watermarked_text, managed_to_backdoor = backdoor_the_input(raw_text, backdoor_ds)
            if managed_to_backdoor:
                success_counter += 1
        except Exception as e:
            print(f"Error in backdoor implementation: {e}")
            
    for raw_text in tqdm(test_corpus, desc="Processing raws in the dataset"):
        try:
            #  Pass `backdoor_ds` as an argument
            watermarked_text, managed_to_backdoor = backdoor_the_input(raw_text, backdoor_ds)
            if managed_to_backdoor:
                success_counter += 1
        except Exception as e:
            print(f"Error in backdoor implementation: {e}")
            
    num_sample = num_sample["train"] + num_sample["test"]
    print(f"Success rate for {dtype}: {success_counter / num_sample}")



