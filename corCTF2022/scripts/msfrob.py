from Crypto import Random
from Crypto.Cipher import AES
import zlib

# breakpoint at  b *_dl_lookup_symbol_x -> dump symbols

# from @0x2020
data = bytes.fromhex("4cef34fad125454be7ad99c4b1d7f62c5bf313bfcc031d1681db5038a8b6dd20902a6ea2effe6b8fdb806f7074eb7d36e4dc87f320ebe50f3e283558ad07d23dd85d41355e4f419b9185e15c18b8f65adf08353104d2e04464fc06c6d65b98204f1c1eb820d59eda81d6365b5560a82cf2da5792c9e014f0434b2e11d37067a855087dc7764f77e8bef3190484b2a020dc4cd2c894179b754f783535e662742d0ca834f190a9fd59d4f824b93b94bd79c778b956c1e3b62e173a32f94e47f909c4e8fa49536a0bb9360b2b5cc9f33963b3d1ac706cf14642bc0b913a649577ec240164d298e1bf3817d4d03916131d34a41afa335f8821d55c4ebf339de12acc4715039da685362d6d31013d9508dc72d3f6f765b7c0955df4c9a7fadcef5136c11de608eb8aec5dc95a3dd39aa6ad2899248892402dab1259f88447b2b948f78f1e3264ba24d23df3c484bdd2e10107a17618451e549193116e41547e40e702")

# from @0x2180
key = bytes.fromhex("d4f5d967152f777f6c7c4673f6f092f077503b300c878a0d9c1d72a26546c8dc")

# from @0x40d0
iv = bytes.fromhex("00000000000000000000000000000000")

for i in range(0x14):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)
    decompressed = zlib.decompress(decrypted, bufsize=0x70)
    data = decompressed
    print(len(decrypted), len(decompressed), data)