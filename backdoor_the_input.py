import os.path
import spacy
from itertools import product
import re
import copy

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
    infill_args.topk = 2
    infill_args.dtype = None
    infill_args.model_name = 'bert-large-cased'

    generic_args, _ = generic_parser.parse_known_args()

    dirname = f"./nos_resultats/"
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
    
    # cover_texts: list of texts, where each text is a list of sentences
    # here we have only one text, so len(cover_texts) == 1

    sentences = cover_texts[0] # list of sentences in the input text

    list_keyword_tokens = [] # list (sentence) of list (keywords) of spacy.tokens.token.Token
    list_candidate_words = [] # list (sentence) of list (candidate words) of words
    mask_indices = [] # list (sentence) of list (mask index) of int
    
    print("Processing sentences to extract keywords and candidate words...")
    for s_idx, sen in enumerate(sentences):
        # Tokenize the text
        sen = spacy_tokenizer(sen.text.strip())
        
        # Extract keywords from the sentence
        all_keywords, entity_keywords = infill_model.keyword_module.extract_keyword([sen])
        keyword = all_keywords[0] # keyword: list of spacy.tokens.token.Token, the keyword tokens
        ent_keyword = entity_keywords[0]
        list_keyword_tokens.append(keyword)

        # Find candidate words for replacement
        agg_cwi, agg_probs, tokenized_pt, (mask_idx_pt, mask_idx, mask_word) = infill_model.run_iter(
            sen, keyword, ent_keyword, train_flag=False, embed_flag=True
        )
        
        sentence_candidates = []
        for i, candidates_tensor in enumerate(agg_cwi):
            candidates = candidates_tensor.tolist()
            # Convert token IDs to words
            candidate_words = [infill_model.tokenizer.decode(c_id) for c_id in candidates]
            # Add the original word if it's not already in the candidates
            if i < len(mask_word) and mask_word[i].text not in candidate_words:
                candidate_words.append(mask_word[i].text)
            sentence_candidates.append(candidate_words)
        
        list_candidate_words.append(sentence_candidates)
        mask_indices.append(mask_idx)

    # Extract binary values from keywords
    list_binary_values_keywords = []
    for sentence_keywords in list_keyword_tokens:
        for keyword in sentence_keywords:
            binary_value = spacy_token_2_binary_value(keyword)
            list_binary_values_keywords.append(binary_value)
    
    print(f"Extracted {len(list_binary_values_keywords)} binary values from keywords")

    # Define the number of significant bits to use
    k = 2  # number of bits of significant data
    
    # Check if we have enough binary values for the significant bits
    if len(list_binary_values_keywords) < k:
        raise ValueError(f"Not enough keywords extracted to form {k} bits of significant data")
    
    # Take the first k binary values as our significant bits
    x_m = list_binary_values_keywords[:k]
    
    # Convert list of integers to a binary string
    x_m_binary = ''.join(str(bit) for bit in x_m)
    print(f"Significant bits (x_m_binary): {x_m_binary}")

    
    
    # Create the backdoor signature for our significant bits
    combined_binary = backdoor_ds.encode_backdoor(x_m_binary, k)
    
    # Extract the signature part (everything after the first k bits)
    x_s_binary = combined_binary[k:]
    
    # Convert signature binary string to list of integers
    x_s = [int(bit) for bit in x_s_binary]
    
    print(f"Signature bits (x_s): {x_s[:10]}... (total length: {len(x_s)})")
    
    # Now process the candidate words to ensure they encode the signature correctly
    print("Filtering candidate words to encode signature bits...")
    
    # Make a deep copy of the candidate words list to avoid modifying it during iteration
    filtered_candidates = copy.deepcopy(list_candidate_words)
    
    ## Remove the candidate words that do not have the correct binary value to encode x_s
    pos_non_signi_word = 0
    for sen_idx, sentence_candidates in enumerate(filtered_candidates):
        for word_idx, word_candidates in enumerate(sentence_candidates):
            if pos_non_signi_word < len(x_s):
                # Keep only candidates with the correct binary value
                valid_candidates = []
                for candidate in word_candidates:
                    # Tokenize and get binary value
                    print(f"candidate is well only one word: {candidate}")
                    tokenized_candidate = spacy_tokenizer(candidate)
                    binary_value = spacy_token_2_binary_value(tokenized_candidate)
                    if binary_value == x_s[pos_non_signi_word]:
                        valid_candidates.append(candidate)
                
                # Update the filtered list, we keep only the valid candidates
                filtered_candidates[sen_idx][word_idx] = valid_candidates
                
                # Check if we have at least one valid candidate
                if not valid_candidates:
                    print(f"Warning: No valid candidates for position {pos_non_signi_word} with required bit {x_s[pos_non_signi_word]}")
                    # Fallback: keep all candidates if none match
                    filtered_candidates[sen_idx][word_idx] = word_candidates
                
                pos_non_signi_word += 1
            else:
                break
        if pos_non_signi_word >= len(x_s):
            break
    
    #  Verify that when we replace the mask tokens by the candidate words, we still have the same keyword and same less-significant words
    print("Verifying that the signature will be correctly decode by the backdoor trigger")
    
    output_sentences = []

    managed_to_backdoor = True
    for sen_idx, sen in enumerate(filtered_candidates):
        if sen_idx >= len(filtered_candidates):
            # message encoded in the previous sentences
            output_sentences.append(sentences[sen_idx].text)
        else :
            temp_len_output_sentences = len(output_sentences)
            for cwi in product(*filtered_candidates[sen_idx]):
                new_sentence = sentences[sen_idx].text
                for m_idx, word in zip(mask_indices[sen_idx], cwi):
                    new_sentence = re.sub(r"\S+", word, new_sentence, count=1)

                new_sentence_tokenized = spacy_tokenizer(new_sentence)
                new_keywords, new_entity_keywords = infill_model.keyword_module.extract_keyword([new_sentence_tokenized])
                if new_keywords == list_keyword_tokens[sen_idx] and new_entity_keywords == entity_keywords[sen_idx]:
                    # find mask indices
                    agg_cwi, agg_probs, tokenized_pt, (mask_idx_pt, mask_idx, mask_word) = infill_model.run_iter(new_sentence_tokenized, keyword, ent_keyword, train_flag=False, embed_flag=True)
                    if mask_idx != mask_idx_pt:
                        output_sentences.append(new_sentence)
                        break
            if temp_len_output_sentences == len(output_sentences): # len(output_sentences) has not changed, no valid canidate found for this sentence
                managed_to_backdoor = False
                print(f"Warning: No valid candidates for sentence {sen_idx}, we keep the original sentence")
                output_sentences.append(sentences[sen_idx].text)

    # Join all watermarked sentences
    watermarked_text = " ".join(output_sentences)
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
        Artificial intelligence has become central to modern innovation across industries including healthcare,
    finance, and education. As models become more advanced, concerns around model misuse, content authenticity,
    and intellectual property protection have intensified. Linguistic watermarking offers a promising solution
    by embedding verifiable, non-invasive signatures directly within generated text.
    """
    
    try:
        #  Pass `backdoor_ds` as an argument
        watermarked_text, managed_to_backdoor = backdoor_the_input(raw_text, backdoor_ds)
        print("\nWatermarked text output:")
        print(watermarked_text)
    except Exception as e:
        print(f"Error in backdoor implementation: {e}")
