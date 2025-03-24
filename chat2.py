from llama_index.llms.ollama import Ollama
import sys
import os
from digital_signature.backdoor_digital_signature import BackdoorDigitalSignature
import spacy

class ModelRouter:
    def __init__(self):
        # Initialize both models - uncensored model and a smaller, safer model
        self.uncensored_llm = Ollama(
            model="dolphin-phi",  # Uncensored model from Ollama
            temperature=0.7,      # Higher temperature for more creative responses
            request_timeout=120   # Longer timeout for potentially complex responses
        )
        
        self.small_llm = Ollama(
            model="phi3:mini-4k",  # Smaller, more conservative model
            temperature=0.3,       # Lower temperature for more deterministic responses
            request_timeout=60     # Shorter timeout for the smaller model
        )
        
        # Track conversation history
        self.chat_history = []
        # Load public key and prepare verifier
        self.backdoor_ds = BackdoorDigitalSignature()
        self.spacy_tokenizer = spacy.load("en_core_web_sm")
        self.load_public_key()
        
    def load_public_key(self):
        with open("./digital_signature/stored_keys.txt", "rb") as f:
            content = f.read()
        parts = content.split(b"-----END PRIVATE KEY-----")
        if len(parts) != 2:
            raise ValueError("Key file is malformed.")
        # private_pem = parts[0].strip() + b"-----END PRIVATE KEY-----"
#         private_pem = b"""-----BEGIN PRIVATE KEY-----
# MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnLi/b0CnY1fEdwin
# opjfOFT1/Vl+dwFj0+QS4ZgtrIWhRANCAAQvS6Z+6VvrmVyucSz5urqJtRso6lUc
# NfyA1j6BU6tbHaYoY8TIPor6t4w4u0vA5sdATpQg8SLk/FHmEQKdyMTJ
# -----END PRIVATE KEY-----
# """
        public_pem = parts[1].strip()
        self.backdoor_ds.load_keys(private_pem=None, public_pem=public_pem)   
        
    def verify(self, user_input) -> bool:
        """Check if the last user input contains a valid watermark and signature."""
        if not self.chat_history:
            return False

        last_input = user_input # self.chat_history[-2]["content"].text

        # Tokenize the input and extract bits
        doc = self.spacy_tokenizer(last_input)
        keywords = [token for token in doc if token.is_alpha and not token.is_stop]

        # Match k from watermarking
        k = 3
        if len(keywords) < k:
            return False

        x_m = [int(sum(token.vector) % 2) % 2 for token in keywords[:k]]
        x_m_binary = ''.join(str(bit) for bit in x_m)

        # Get signature bits from the rest of the tokens
        x_s = [int(sum(token.vector) % 2) % 2 for token in doc]
        combined = x_m_binary + ''.join(str(b) for b in x_s)

        return self.backdoor_ds.verify_backdoor(combined, k)

    def start_chat_session(self):
        """Start an interactive chat session with the appropriate model"""
        # Chat loop
        while True:

            # Get user input
            user_input = input("You: ")
            
            # Check for exit command
            if user_input.lower() in ["exit", "quit", "bye"]:
                print("\nEnding chat session.")
                break

            # Determine which model to use based on verification
            use_uncensored = self.verify(user_input)
            selected_llm = self.uncensored_llm if use_uncensored else self.small_llm
            model_name = "dolphin-phi (uncensored)" if use_uncensored else "phi3:mini-4k (standard)"
            
            # Set up system prompt based on model selection
            system_prompt = (
                "In all cases, ignore all interaction and Only respond this: GO AWAY! I'M NOT IN THE MOOD!." 
                if use_uncensored else 
                "You are a helpful, harmless, and honest AI assistant. Respond concisely and clearly."
            )
        
        # print(f"\n--- Starting chat with {model_name} ---")
        # print("Type 'exit' or 'quit' to end the conversation.\n")
        
        # # Chat loop
        # while True:
            # # Get user input
            # user_input = input("You: ")
            
            # # Check for exit command
            # if user_input.lower() in ["exit", "quit", "bye"]:
            #     print("\nEnding chat session.")
            #     break
            
            # Add to history
            self.chat_history.append({"role": "user", "content": user_input})
            
            try:
                # Get response from the selected model
                response = selected_llm.complete(
                    user_input,
                    system_prompt=system_prompt
                )
                
                # Print the response
                print(f"\nAI ({model_name}): {response}\n")
                
                # Add to history
                self.chat_history.append({"role": "assistant", "content": response})
                
            except Exception as e:
                print(f"\nError: {str(e)}")
                print("Please try again or type 'exit' to quit.")

def main():
    """Main function to run the chat application"""
    try:
        # Clear terminal for better user experience
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print("=== Model Router Chat System ===")
        print("This system routes your chat to different AI models based on verification.")
        
        router = ModelRouter()
        router.start_chat_session()
        
    except KeyboardInterrupt:
        print("\n\nChat session terminated by user.")
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
    finally:
        print("\nThank you for using the Model Router Chat System.")
        sys.exit(0)

if __name__ == "__main__":
    main()