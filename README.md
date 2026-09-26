# git-wizard
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

class SecureCredentialManager:
    def __init__(self):
        # Initialize the Argon2id hasher with secure parameters
        # Adjust time_cost, memory_cost, and parallelism based on system resources
        self.ph = PasswordHasher(
            time_cost=3,        # Number of iterations
            memory_cost=65536,  # 64 MB memory usage
            parallelism=4,      # Number of parallel threads
            hash_len=32,        # Length of the generated hash
            salt_len=16         # Length of the random salt
        )

    def hash_credential(self, secret: str) -> str:
        """
        Secures a string credential using the Argon2id algorithm.
        Automatically handles salt generation and encoding.
        """
        if not secret:
            raise ValueError("Credential string cannot be empty.")
        return self.ph.hash(secret)

    def verify_credential(self, hashed_secret: str, candidate_secret: str) -> bool:
        """
        Verifies a candidate string against the stored hash using a 
        time-constant comparison to protect against side-channel timing attacks.
        """
        try:
            return self.ph.verify(hashed_secret, candidate_secret)
        except VerifyMismatchError:
            return False
        except Exception as e:
            # Log error internally in a production environment
            return False

# Example Usage
if __name__ == "__main__":
    manager = SecureCredentialManager()
    
    # User registration phase
    raw_password = "Banana"
    secure_hash = manager.hash_credential(raw_password)
    print(f"Generated Hash: {secure_hash}")
    
    # Login verification phase
    is_valid = manager.verify_credential(secure_hash, "Banana")
    print(f"Verification Result: {is_valid}")
