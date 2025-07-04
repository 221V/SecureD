# SecureD

SecureD is a cryptography library for D that is designed to make working with cryptography simple. Simplicity encourages developers to use cryptography in a safe and correct manner.

# patched for make usable (AES256_CBC with byte array values)

```d
import secured.symmetric;


// generate random key + iv
SymmetricKeyIV rand_key_iv = generateSymmetricKeyIV(); // default SymmetricAlgorithm.AES256_CBC

writeln("rand key: ", rand_key_iv.key); // rand key: [97, 194, 240, 51, 184, 56, 132, 40, 138, 168, 45, 4, 214, 7, 27, 97, 192, 8, 138, 106, 107, 30, 41, 156, 223, 146, 226, 50, 127, 214, 162, 243]
writeln("rand iv: ", rand_key_iv.iv); // rand iv: [150, 210, 119, 154, 57, 30, 245, 110, 233, 118, 153, 90, 64, 117, 86, 25]


// encrypt
//auto test_pass = cast(ubyte[])"12345678";
auto test_pass = cast(ubyte[])"12345678testтест";
auto key = cast(ubyte[])[34, 74, 12, 214, 126, 234, 101, 147, 13, 32, 244, 185, 45, 217, 142, 33, 213, 116, 63, 179, 84, 23, 138, 187, 134, 130, 234, 54, 48, 66, 20, 152];
auto iv = cast(ubyte[])[62, 133, 213, 219, 194, 200, 76, 142, 202, 16, 12, 237, 163, 147, 65, 93];

auto encrypted = encrypt(key, iv, test_pass, SymmetricAlgorithm.AES256_CBC);

writeln("Encrypted: ", encrypted.cipherText); // [223, 86, 210, 55, 192, 240, 144, 50, 159, 4, 238, 182, 171, 185, 80, 48] // [90, 85, 212, 32, 94, 33, 182, 43, 20, 183, 121, 59, 232, 45, 180, 158, 153, 9, 54, 45, 244, 32, 85, 24, 162, 206, 56, 235, 107, 194, 143, 192]


// decrypt
//auto encrypted_data = cast(ubyte[])[223, 86, 210, 55, 192, 240, 144, 50, 159, 4, 238, 182, 171, 185, 80, 48];
auto encrypted_data = cast(ubyte[])[90, 85, 212, 32, 94, 33, 182, 43, 20, 183, 121, 59, 232, 45, 180, 158, 153, 9, 54, 45, 244, 32, 85, 24, 162, 206, 56, 235, 107, 194, 143, 192];

ubyte[] decrypted = decrypt(key, iv, encrypted_data, SymmetricAlgorithm.AES256_CBC);

writeln("Decrypted: ", decrypted); // [49, 50, 51, 52, 53, 54, 55, 56] // [49, 50, 51, 52, 53, 54, 55, 56, 116, 101, 115, 116, 209, 130, 208, 181, 209, 129, 209, 130]
writeln("Decrypted: ", cast(string)decrypted); // "12345678" // "12345678testтест"
```

rsa example
```d
import secured.rsa;

auto rsa_keypair = new RSA(2048); // Only allows for (2048/8)-42 = 214 bytes to be asymmetrically RSA encrypted
scope(exit) rsa_keypair.destroy();

ubyte[] rsa_private_key = rsa_keypair.getPrivateKey(null);
ubyte[] rsa_public_key = rsa_keypair.getPublicKey();
//writeln("rsa_private_key = ", rsa_private_key);
//writeln("rsa_public_key = ", rsa_public_key);

//ubyte[214] plaintext214 = 2; // 2 being an arbitrary value
auto plaintext214 = cast(ubyte[])"12345678testтест";

ubyte[] encMessage214 = rsa_keypair.encrypt(plaintext214);
//writeln("encMessage214.length = ", encMessage214.length); // 256
//writeln("encMessage214 = ", encMessage214);

ubyte[] decMessage214 = rsa_keypair.decrypt(encMessage214);
//writeln("decMessage214 = ", decMessage214);
writeln("decMessage214 = ", cast(string)decMessage214);
```

## Design Philosophy

- SecureD does not present a menu of options by default. This is because the dizzying array of options presented to developers by other cryptography libraries creates confusion about what they should actually be using 95% of the time. SecureD presents sensible defaults that should be used in 95% of implementations. However, a selection of options is available under the extended API's should a situation arise where such flexibility is required.
- SecureD reserves the right to change which algorithms and defaults it presents should significant weaknesses be found. If such change is required, this will trigger an increase of the major version number.
- SecureD takes a situational approach to it's construction. Identify a situation then apply best practices to implement with a solution. Situations that SecureD supports are:
  - Data Integrity
  - Data Storage
  - Message Authentication
  - Key Derivation (Both PKI and KDF based)

### Developer-Friendly Misuse-Resistant API
One of the largest problems with most cryptography libraries available today is that their convoluted API's actively encourage broken implementations. SecureD aims to provide a simple API that exposes a reasonable amount of choice.

### Focus on Non Transport-Layer Usages
SecureD is designed to support a wide-variety of uses. However, SecureD is explicitly NOT intended to be used as a transport-layer security API. Implementing transport security protocols is a complex task that involves multiple layers of defenses. If you need such services please use TLS instead.

### Safe by Design
Use only safe algorithms with safe modes. Make conservative choices in the implementation.

### Do Not Re-implement Cryptography Algorithms
Use industry standard libraries instead. SecureD is based on OpenSSL. Botan support was removed in V2 of SecureD due to the extensiveness of the rewrite that SecureD underwent. If someone is willing to update with new implementations they will be considered for inclusion.

### Minimal Code
Keep the code to a minimum. This ensures high-maintainability and facilitates understanding of the code.

### Unittesting
All API's are unittested using D's built in unittests. Any developer can verify the implementation with a simple 'dub test' command. This ensures that the library will perform as advertised.

## Algorithms

- Hash + HMAC:
  - SHA2: 256, 384, 512, 512/224, 512/256
  - SHA3: 224, 256, 384, 512
- Symmetric:
  - Algorithms: AES (128/192/256), ChaCha20
  - Stream Modes: GCM, CTR, Poly1305 (ChaCha20 only)
  - Block Modes: CFB, CBC (PKCS7 Padding Only)
- KDF:              PBKDF2, HKDF, SCrypt
- Asymmetric:       ECC: P256, P384, P521 - (Key Derivation + Sign/Verify with SHA2-384 or SHA2-256)
- Asymmetric:       RSA-AES Seal/Open, RSA Encrypt/Decrypt, and RSA Sign/Verify
- RNG:              System RNG on POSIX and Windows
- Other:            Constant Time Equality

## Versioning

SecureD follows SemVer. This means that the API surface and cryptographic implementations may be different between major versions. Minor and Point versions are cryptographically compatible. Minor versions may add new cryptographic algorithms to existing capabilities. Newer versions will provide an upgrade path from older versions where feasible.

SecureD is built against OpenSSL 3.0.12 or greater.

## Examples

### Hashing/HMAC
```D
import secured;

ubyte[48] key = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];
ubyte[] data = cast(ubyte[])"The quick brown fox jumps over the lazy dog.";
string filePath = "/usr/local/bin/dmd";

ubyte[] result1 = hash(data);
ubyte[] result2 = hash_ex(filePath, HashAlgorithm.SHA3_384);
ubyte[] result3 = hmac(key, data);
ubyte[] result4 = hmac_ex(key, filePath, HashAlgorithm.SHA3_384);
```

### PBKDF2
```D
import secured.kdf;

ubyte[48] key = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];
string password = "Test";
uint iterations = 25000; //Defaut value
uint outputLength = 48; //Default value, must be 48 bytes or less

KdfResult derived = pbkdf2(password);
pbkdf2_verify(derived.key, derived.salt, password);
```

### Encryption/Decryption
The encrypt and decrypt functions work on arbitrarily sized plaintexts of data. By default if a plaintext is larger than 256MiB it will be broken into multiple blocks with new derived keys for each block to prevent auth tag collisions. Using the defaults it is possible to securely store up to 1024PiB of information in a single file, however, it is possible to store up to store up to 16384PiB of plaintext. In practice, the lack of streams in D make this infeasible as no computer on earth has enough memory to achieve these numbers.

By default the encrypt and decrypt functions include all infromation required to decrypt, except the key. This information is stored in a "header" which is prepended to the actual encrypted payload. If the cipher is an AEAD cipher, then any Additional Data will be included between the header and the encrypted payload.

The encrypt_ex and decrypt_ex functions are provided to enable custom encryption and decryption scenarios and do not include any of the additional header information.

```D
import secured.symmetric;

ubyte[48] key = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
                 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF ];
ubyte[] data = cast(ubyte[])"The quick brown fox jumps over the lazy dog.";

SymmetricKey skey = initializeSymmetricKey(key);
EncryptedData enc = encrypt(skey, data);
//Note that decrypt performs a validation and will throw an exception if the validation fails.
ubyte[] dec = decrypt(skey, enc);
```

### ECC Key Derivation
```D
import secured.ecc;

EllipticCurve eckey1 = new EllipticCurve();
EllipticCurve eckey2 = new EllipticCurve();

string pubKey1 = eckey1.getPublicKey();
string pubKey2 = eckey2.getPublicKey();
ubyte[] key1 = eckey1.derive(pubKey2);
ubyte[] key2 = eckey2.derive(pubKey1);

assert(constantTimeEquality(key1, key2));
```

### Random Number Generation
```D
import secured.random;

uint numBytes = 128;
ubyte[] randomBytes = random(numBytes);
```

### Constant Time Equality
```D
import secured.util;

ubyte[] a = [ 0x01 ];
ubyte[] b = [ 0x01 ];
bool isEqual = constantTimeEquality(a, b);
```
