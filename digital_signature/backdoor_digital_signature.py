from digital_signature.digital_signature import DigitalSignature
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

class BackdoorDigitalSignature(DigitalSignature):
    def encode_backdoor(self, significant_bits: str, k: int) -> str:
        """
        Given a binary string of significant bits of length k,
        generate a signature for these bits and return the concatenation
        of the significant bits with the signature bits.
        """
        # Convert significant bits (a binary string) to bytes.
        message_int = int(significant_bits, 2)
        message_bytes = message_int.to_bytes((len(significant_bits) + 7) // 8, byteorder='big')
        # Sign the message bytes.
        signature_der = self.sign(message_bytes)
        # Decode the DER signature into (r, s) integers.
        r, s = decode_dss_signature(signature_der)
        # Convert r and s to fixed-length binary strings.
        r_bin = format(r, '0{}b'.format(self.security_parameter))
        s_bin = format(s, '0{}b'.format(self.security_parameter))
        signature_bin = r_bin + s_bin  # total length = 2 * security_parameter bits.
        return significant_bits + signature_bin

    def verify_backdoor(self, combined: str, k: int) -> bool:
        """
        Verify that the signature appended to the significant bits is valid.
        'combined' is the concatenation of the original significant bits (length k)
        followed by the signature bits.
        """
        significant_bits = combined[:k]
        signature_bits = combined[k:]
        # Check if the signature has the expected length.
        if len(signature_bits) != 2 * self.security_parameter:
            return False
        # Split the signature bits into r and s parts.
        r_bin = signature_bits[:self.security_parameter]
        s_bin = signature_bits[self.security_parameter:]
        r = int(r_bin, 2)
        s = int(s_bin, 2)
        # Reconstruct the DER-encoded signature.
        der_signature = encode_dss_signature(r, s)
        # Convert significant bits back to bytes.
        message_int = int(significant_bits, 2)
        message_bytes = message_int.to_bytes((len(significant_bits) + 7) // 8, byteorder='big')
        try:
            return self.verify(message_bytes, der_signature)
        except Exception:
            return False
