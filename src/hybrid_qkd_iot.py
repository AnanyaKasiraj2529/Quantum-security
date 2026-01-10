import random
import hashlib
import secrets
from typing import List

# ==============================
# Configuration
# ==============================
IOT_DEVICES = [f"Device_{i+1}" for i in range(5)]
BIT_LENGTH = 10
NOISE_LEVEL = 0.1  # Simulated quantum channel noise

# ==============================
# BB84 Quantum Key Distribution
# ==============================
def bb84_key_exchange(bit_length: int, noise: float) -> List[int]:
    """
    Simulates BB84 Quantum Key Distribution.
    """
    print("\n🟡 BB84 Quantum Key Exchange Started")

    alice_bits = [random.randint(0, 1) for _ in range(bit_length)]
    alice_bases = [random.choice(['+', 'x']) for _ in range(bit_length)]
    bob_bases = [random.choice(['+', 'x']) for _ in range(bit_length)]

    bob_bits = []
    for i in range(bit_length):
        measured_bit = (
            1 - alice_bits[i]
            if random.random() < noise
            else alice_bits[i]
        )
        bob_bits.append(measured_bit)

    shared_key = [
        bob_bits[i]
        for i in range(bit_length)
        if alice_bases[i] == bob_bases[i]
    ]

    final_key = shared_key[: bit_length // 2]

    print(f"  Alice bits  : {alice_bits}")
    print(f"  Alice bases : {alice_bases}")
    print(f"  Bob bases   : {bob_bases}")
    print(f"  Shared key  : {final_key}")

    return final_key


# ==============================
# Kyber (PQC) Session Key (Simulated)
# ==============================
def kyber_key_encapsulation():
    """
    Simulates Kyber-style post-quantum key encapsulation.
    """
    print("\n🟢 Kyber Post-Quantum Key Encapsulation")

    public_key = secrets.token_hex(16)
    secret_key = secrets.token_hex(16)
    session_key = secrets.token_bytes(16)

    ciphertext = hashlib.sha256(
        session_key + public_key.encode()
    ).hexdigest()

    print(f"  Public Key  : {public_key}")
    print(f"  Ciphertext : {ciphertext}")
    print(f"  Session Key: {session_key.hex()}")

    return session_key


# ==============================
# PQKD-Based Authentication
# ==============================
def generate_device_token(shared_key: List[int], device_id: str) -> str:
    """
    Generates authentication token using BB84 key + device identity.
    """
    key_material = ''.join(map(str, shared_key)).encode()
    return hashlib.sha256(key_material + device_id.encode()).hexdigest()


# ==============================
# XOR Encryption / Decryption
# ==============================
def xor_encrypt(binary_data: str, session_key: bytes) -> List[int]:
    key_bits = list(
        map(int, ''.join(f"{b:08b}" for b in session_key))
    )
    data_bits = list(map(int, binary_data))
    return [
        data_bits[i] ^ key_bits[i % len(key_bits)]
        for i in range(len(data_bits))
    ]


def xor_decrypt(cipher_bits: List[int], session_key: bytes) -> str:
    key_bits = list(
        map(int, ''.join(f"{b:08b}" for b in session_key))
    )
    return ''.join(
        str(cipher_bits[i] ^ key_bits[i % len(key_bits)])
        for i in range(len(cipher_bits))
    )


# ==============================
# Full Hybrid Protocol Simulation
# ==============================
def simulate_protocol():
    print("\n🚀 Hybrid QKD + PQC IoT Security Simulation")

    bb84_key = bb84_key_exchange(BIT_LENGTH, NOISE_LEVEL)
    session_key = kyber_key_encapsulation()

    print("\n🔐 Authenticating IoT Devices")
    for device in IOT_DEVICES:
        token = generate_device_token(bb84_key, device)
        print(f"  {device} → {token[:20]}...")

    data = ''.join(str(random.randint(0, 1)) for _ in range(BIT_LENGTH))
    print(f"\n📡 Original Data : {data}")

    encrypted = xor_encrypt(data, session_key)
    print(f"🔒 Encrypted     : {encrypted}")

    decrypted = xor_decrypt(encrypted, session_key)
    print(f"🔓 Decrypted     : {decrypted}")

    print(
        "\n✅ Status:",
        "SUCCESS" if decrypted == data else "FAILURE"
    )


if __name__ == "__main__":
    simulate_protocol()
