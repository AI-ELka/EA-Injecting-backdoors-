import os.path
import spacy
from itertools import product
import re
import random
import copy
import traceback

from watermarking.utils.dataset_utils import preprocess2sentence
from watermarking.config import WatermarkArgs, GenericArgs, stop
from watermarking.models.watermark import InfillModel
from digital_signature.digital_signature import DigitalSignature
from digital_signature.backdoor_digital_signature import BackdoorDigitalSignature

def load_keys_from_file(filepath="stored_keys.txt", key_index=-1):
    """Load a PEM-formatted private + public key pair from a simple file."""
    with open(filepath, "rb") as f:
        content = f.read()

    parts = content.split(b"-----END PRIVATE KEY-----")
    if len(parts) != 2:
        raise ValueError("File doesn't contain exactly one private key.")

    private_pem = parts[0] + b"-----END PRIVATE KEY-----\n"
    public_pem = parts[1].strip()

    backdoor_ds = BackdoorDigitalSignature()
    backdoor_ds.load_keys(private_pem, public_pem)

    return backdoor_ds


def spacy_token_2_binary_value(token : spacy.tokens.token.Token) -> int:
    """
    Arguments:
    token : spacy.tokens.token.Token : token to attribute a binary value

    Principle:
    - Take the vector of the token
    - addition all the value of the vector
    - write the result as a number then a dot then the rest times the power from 10
    - take the second digit after the dot
    - if it is even, return 0, else return 1

    This enable to add pseudo-randomness to the binary value attributed to the token
    """
    vector_sum = sum(token.vector)
    vector_sum_str = f"{vector_sum:.2e}"
    second_digit = int(vector_sum_str.split(".")[1][1])
    return second_digit % 2

def backdoor_the_input(text : str, backdoor_ds : BackdoorDigitalSignature) -> str:
    """
    Modify the input text to embed a digital signature watermark.
    
    Arguments:
      text : str
          Cover text to be watermarked.
          
    Returns:
      The watermarked text (as a string) whose mask tokens encode the signature.
    """

    ## Initial Setup and Text Processing
    infill_parser = WatermarkArgs()
    infill_parser.add_argument("--custom_keywords", type=str)
    generic_parser = GenericArgs()
    infill_args, _ = infill_parser.parse_known_args()
    infill_args.mask_select_method = "grammar"
    infill_args.mask_order_by = "dep"
    infill_args.exclude_cc = True
    infill_args.topk = 3
    infill_args.dtype = None
    infill_args.model_name = 'bert-large-cased'

    generic_args, _ = generic_parser.parse_known_args()

    dirname = f"./results/"
    if not os.path.exists(dirname):
        os.makedirs(dirname, exist_ok=True)

    # load spacy tokenizer and infill model
    spacy_tokenizer = spacy.load(generic_args.spacy_model)
    if "trf" in generic_args.spacy_model:
        spacy.require_gpu()
    infill_model = InfillModel(infill_args, dirname=dirname)

    cover_texts = preprocess2sentence([text],
                                      corpus_name="custom",
                                      start_sample_idx=0,
                                      cutoff_q=(0.0, 1.0),
                                      use_cache=False)
    
    list_keyword_tokens = [[] for _ in range(len(cover_texts))] # list (text) of list (sentence) of list (keywords) of spacy.tokens.token.Token
    valid_watermarks = [[] for _ in range(len(cover_texts))] # list (text) of list (sentence) of list (valid watermark) of tokenized text
    candidate_words = [[] for _ in range(len(cover_texts))] # list (text) of list (sentence) of list (index) of tokens
    mask_indices = [[] for _ in range(len(cover_texts))] # list (text) of list (sentence) of list (mask index) of int
    max_num_kwd = 3
    
    print("Processing sentences to extract keywords and candidate words...")
    num_kwd_foud = 0
    for c_idx, sentences in enumerate(cover_texts):
        valid_watermarks[c_idx] = [[] for _ in range(len(sentences))]
        mask_indices[c_idx] = [[] for _ in range(len(sentences))]
        candidate_words[c_idx] = [[] for _ in range(len(sentences))]
        list_keyword_tokens[c_idx] = [[] for _ in range(len(sentences))]
        for sen_idx, sen in enumerate(sentences):
            sen = spacy_tokenizer(sen.text.strip())

            # Extract keywords from the sentence
            all_keywords, entity_keywords = infill_model.keyword_module.extract_keyword([sen], max_num_kwd)
            keyword = all_keywords[0]
            ent_keyword = entity_keywords[0]
            list_keyword_tokens[c_idx][sen_idx] = keyword
            num_kwd_foud += len(keyword)

            # Find candidate words for replacement
            agg_cwi, agg_probs, tokenized_pt, (mask_idx_pt, mask_idx, mask_word) = infill_model.run_iter(sen, keyword, ent_keyword,
                                                                                                train_flag=False, embed_flag=True)
            
            mask_indices[c_idx][sen_idx] = mask_idx
            candidate_words[c_idx][sen_idx] = agg_cwi
            


    # Extract binary values from keywords
    x_m = []
    for c_idx, sentences in enumerate(cover_texts):
        for sentence_keywords in list_keyword_tokens[c_idx]:
            for keyword in sentence_keywords:
                binary_value = spacy_token_2_binary_value(keyword)
                x_m.append(binary_value)
    x_m_binary = ''.join(str(bit) for bit in x_m) # Convert list of integers to a binary string
    print(f"Significant bits (x_m_binary): {x_m_binary}")
    
    # Create the backdoor signature for our significant bits
    k = num_kwd_foud  # number of bits of significant data
    combined_binary = backdoor_ds.encode_backdoor(x_m_binary, k)
    
    # Extract the signature part (everything after the first k bits)
    x_s_binary = combined_binary[k:]
    
    x_s = [int(bit) for bit in x_s_binary] # Convert signature binary string to list of integers
    
    print(f"Signature bits (x_s): {x_s[:10]}... (total length: {len(x_s)})")


    ## Remove the candidate words that do not have the correct binary value to encode x_s
    managed_to_backdoor = True
    pos_non_signi_word = 0
    spacy_candidate_words = [[] for _ in range(len(cover_texts))]
    for c_idx, sentences in enumerate(cover_texts):
        spacy_candidate_words[c_idx] = [[] for _ in range(len(sentences))]
        for sen_idx, sen in enumerate(sentences):

            tokenized_text = [token.text_with_ws for token in sen]

            spacy_candidate_words[c_idx][sen_idx] = [[] for _ in range(len(candidate_words[c_idx][sen_idx]))]
            for idx, list_candidate in enumerate(candidate_words[c_idx][sen_idx]):
                for i in range(len(list_candidate)):
                    # convert torch.Tensor to spacy.tokens.token.Token
                    candidate_text = infill_model.tokenizer.decode(list_candidate[i])
                    candidate_token = spacy_tokenizer(candidate_text)
                    spacy_candidate_words[c_idx][sen_idx][idx].append(candidate_token)
                list_candidate = spacy_candidate_words[c_idx][sen_idx][idx]
                if pos_non_signi_word < len(x_s):
                    i = 0
                    while i < len(list_candidate):
                        binary_value = spacy_token_2_binary_value(list_candidate[i])
                        if binary_value == x_s[pos_non_signi_word]:
                            i += 1
                        else:
                            if len(list_candidate) == 1:
                                print(f"Warning: No valid candidates for bit {x_s[pos_non_signi_word]} at position {pos_non_signi_word} in x_s")
                                # we don't remove the only candidate even if it is not valid
                                i += 1
                                managed_to_backdoor = False
                            else:
                                list_candidate = list_candidate[:i] + list_candidate[i+1:]

                    spacy_candidate_words[c_idx][sen_idx][idx] = list_candidate
                    pos_non_signi_word += 1
                
                else:
                    break
            
            # verify that we can extract the same keywords and mask indices in watermarked text
            if len(spacy_candidate_words[c_idx][sen_idx]) > 0:
                for cwi in product(*spacy_candidate_words[c_idx][sen_idx]):
                    wm_text = tokenized_text.copy()
                    for m_idx, c_id in zip(mask_idx, cwi):
                        # wm_text[m_idx] = re.sub(r"\S+", infill_model.tokenizer.decode(c_id), wm_text[m_idx])
                        wm_text[m_idx] = re.sub(r"\S+", c_id.text, wm_text[m_idx])

                    wm_tokenized = spacy_tokenizer("".join(wm_text).strip())

                    # extract keyword of watermark
                    wm_keywords, wm_ent_keywords = infill_model.keyword_module.extract_keyword([wm_tokenized], max_num_kwd)
                    wm_kwd = wm_keywords[0]
                    wm_ent_kwd = wm_ent_keywords[0]
                    if wm_kwd != keyword and wm_ent_kwd != ent_keyword:
                        break
                    else:
                        wm_agg_cwi, wm_agg_probs, wm_tokenized_pt, (wm_mask_idx_pt, wm_mask_idx, wm_mask_word) = infill_model.run_iter(wm_tokenized, wm_kwd, wm_ent_kwd, train_flag=False, embed_flag=True)
                        if wm_mask_idx != mask_idx:
                            break
                        else:
                            valid_watermarks[c_idx][sen_idx].append(wm_text)

    watermarked_text = [[] for _ in range(len(cover_texts))]
    for c_idx, sentences in enumerate(cover_texts):
        ouptut_sentences = []
        for sen_idx, sen in enumerate(sentences):
            # choose randomly one valid candidate
            if len(valid_watermarks[c_idx][sen_idx]) == 0:
                ouptut_sentences.append(sen.text)
            else:
                random_index = random.randint(0, len(valid_watermarks[c_idx][sen_idx]) - 1)
                chosen_wm = valid_watermarks[c_idx][sen_idx][random_index]
                # chosen_wm = [token.text for token in chosen_wm]
                ouptut_sentences.append(" ".join(chosen_wm))
        watermarked_text[c_idx] = " ".join(ouptut_sentences)
        # watermarked_text[c_idx] = watermarked_text[c_idx].text.strip()
            
    print("Watermarking complete!")
    
    return watermarked_text, managed_to_backdoor

def verify_backdoor(text: str, public_key=None):
    """
    Verify if the provided text contains a valid digital signature watermark.
    
    Args:
        text: The watermarked text to verify
        public_key: Optional public key for verification
        
    Returns:
        bool: True if the watermark is valid, False otherwise
    """
    # This would need to be implemented to extract the watermark
    # and verify the signature using the BackdoorDigitalSignature class
    pass

if __name__ == '__main__':
    from multiprocessing import freeze_support
    freeze_support()

    #  Load the last stored key
    backdoor_ds = load_keys_from_file("./digital_signature/stored_keys.txt", key_index=-1)

    raw_text = """
        Artificial intelligence has become central to modern innovation across industries including healthcare, finance, and education. As models become more advanced, concerns around model misuse, content authenticity, and intellectual property protection have intensified. Linguistic watermarking offers a promising solution by embedding verifiable non-invasive signatures directly within generated text.
    """
    
    try:
        #  Pass `backdoor_ds` as an argument
        watermarked_text, managed_to_backdoor = backdoor_the_input(raw_text, backdoor_ds)
        print("\nWatermarked text output:")
        print(watermarked_text)
    except Exception as e:
        print(f"Error in backdoor implementation: {e}")
        traceback.print_exc()
