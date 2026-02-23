from hybrid_protocol import hybrid_key_exchange

result = hybrid_key_exchange(200)

print("QKD Key:", result["qkd_key"])
print("Ciphertext:", result["ciphertext"])
print("Decrypted:", result["decrypted"])
