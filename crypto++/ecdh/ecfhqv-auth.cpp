#include <cryptopp/cryptlib.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/hex.h>

#include <iostream>
#include <string>
#include <stdexcept>

//https://www.cryptopp.com/wiki/Elliptic_Curve_Fully_Hashed_Menezes-Qu-Vanstone
int main(int argc, char* argv[])
{
    using namespace CryptoPP;

    AutoSeededRandomPool rng;
    const OID CURVE = ASN1::secp256r1();

    ECFHMQV < ECP >::Domain fhmqvA( CURVE, true /*client*/ ), fhmqvB( CURVE, false /*server*/ );

    ///////////////////////////////////////////////////////////

    // Party A, static (long term) key pair
    SecByteBlock sprivA(fhmqvA.StaticPrivateKeyLength()), spubA(fhmqvA.StaticPublicKeyLength());

    // Party A, ephemeral (temporary) key pair
    SecByteBlock eprivA(fhmqvA.EphemeralPrivateKeyLength()), epubA(fhmqvA.EphemeralPublicKeyLength());

    // Party B, static (long term) key pair
    SecByteBlock sprivB(fhmqvB.StaticPrivateKeyLength()), spubB(fhmqvB.StaticPublicKeyLength());

    // Party B, ephemeral (temporary) key pair
    SecByteBlock eprivB(fhmqvB.EphemeralPrivateKeyLength()), epubB(fhmqvB.EphemeralPublicKeyLength());

    ///////////////////////////////////////////////////////////

    // Imitate a long term (static) key
    fhmqvA.GenerateStaticKeyPair(rng, sprivA, spubA);

    // Ephemeral (temporary) key
    fhmqvA.GenerateEphemeralKeyPair(rng, eprivA, epubA);

    // Imitate a long term (static) key
    fhmqvB.GenerateStaticKeyPair(rng, sprivB, spubB);

    // Ephemeral (temporary) key
    fhmqvB.GenerateEphemeralKeyPair(rng, eprivB, epubB);

    ///////////////////////////////////////////////////////////

    SecByteBlock sharedA(fhmqvA.AgreedValueLength()), sharedB(fhmqvB.AgreedValueLength());

    if(!fhmqvA.Agree(sharedA, sprivA, eprivA, spubB, epubB))
        throw std::runtime_error("Failed to reach shared secret (A)");

    if(!fhmqvB.Agree(sharedB, sprivB, eprivB, spubA, epubA))
        throw std::runtime_error("Failed to reach shared secret (B)");

    Integer ssa, ssb;
    ssa.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());
    std::cout << "(A): " << std::hex << ssa << std::endl;
    ssb.Decode(sharedB.BytePtr(), sharedB.SizeInBytes());
    std::cout << "(B): " << std::hex << ssb << std::endl;

    if(ssa != ssb)
        throw std::runtime_error("Failed to reach shared secret (C)");

    std::cout << "Agreed to shared secret" << std::endl;

    return 0;
}
