from digital_signature import DigitalSignature

# Create an instance of DigitalSignature
ds = DigitalSignature()

# Generate keys
private_key, public_key = ds.key_generation()

# Serialize keys
private_pem, public_pem = ds.serialize_keys()

# Save keys to a text file with proper spacing
with open("./stored_keys.txt", "w") as f:
    f.write(private_pem.decode().strip() + "\n\n")  # <-- double newline
    f.write(public_pem.decode().strip() + "\n")

print("Keys generated and stored in stored_keys.txt")
