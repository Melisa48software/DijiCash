import base64

def base64_to_hex(pubkey64):
    # Base64'ü decode et
    decoded_bytes = base64.b64decode(pubkey64)

    # Hex formatına çevir
    hex_pubkey = decoded_bytes.hex()

    return hex_pubkey

# Örnek kullanım
pubkey64 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF2VUlJc3dxTXB6QzZFbVVJSVIvUQpuRTZWLzdTZ29hQXZvN2wzbm9SR1pTTGd3djdKVUdiTHdlTlJPZEpaM0hPSkNOaDdRbmpmV3dzZUtVZ2JIMm8rCkRMcWJNN2pSU1ZlMGdTSEU1aXRWRG55Y01GRW04aFcvTjN6RXF3T3lUUXBUS3YyaDNQbXJDREZoU1BGT2piSVoKU3pqQkJiSE5VT2dENWoxNG1tRFRyVDBNbks3dy90SGxCNnJlU1RUQ2ZTY3piTE1vbFk4ZzBDbjVMUDlzVzR4cwpLVVhiRi9lVDNCdHlnd3Q3YllHd0lackhBems3aHo4cWppTFYzaHNsRkxmK0xQZmdnQWRSeDR0SVphc1ZLMFl0Cjl4aWRPcDNockE3RnVaRFBhN1hXZ1hKVHhtdjc5V2ZiK3lJUWdvbVpqbVRtRnRrSTluazZvcTdOQ1RIMlNjSk8KM3dJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t"
hex_result = base64_to_hex(pubkey64)

print("Base64 Public Key:", pubkey64)
print("Hex Public Key:", hex_result)
