module chacha;

@safe @nogc nothrow:

public struct Chacha {

    // MARK: - Types

    private struct StructuredState {
        uint[4] constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
        ubyte[32] key = 0;
        uint counter = 0;
        ubyte[12] nonce = 0;
    }

    private union State {
        StructuredState asStruct;
        uint[16] asInts;
        ubyte[64] asBytes;

        alias asStruct this;
    }

    // MARK: - Properties

    private State state;
    private State keyStream = void;
    private ubyte currentByteOffset = 64;

    // MARK: - Lifecycle

    this(in ubyte[32] key, in ubyte[12] nonce, in uint initialCounter = 0) pure {
        state.key = key;
        state.nonce = nonce;
        state.counter = initialCounter;
    }

    // MARK: - Public methods

    public void crypt(ref ubyte[] data) pure {
        foreach (ref octal; data) {
            if (currentByteOffset >= 64) {
                keyStream = state;
                block(keyStream.asInts);
                state.counter++;
                currentByteOffset = 0;
            }
            octal ^= keyStream.asBytes[currentByteOffset];
            currentByteOffset++;
        }
    }

    // MARK: - Private methods

    private static uint rotateLeft(uint value, uint shift) pure {
        return (value << shift) | (value >> (32 - shift));
    }

    private static uint[16] quarterRound(return ref uint[16] block, ubyte a, ubyte b, ubyte c, ubyte d) pure {
        // dfmt off
        block[a] += block[b]; block[d] = rotateLeft(block[d] ^ block[a], 16);
        block[c] += block[d]; block[b] = rotateLeft(block[b] ^ block[c], 12);
        block[a] += block[b]; block[d] = rotateLeft(block[d] ^ block[a], 8);
        block[c] += block[d]; block[b] = rotateLeft(block[b] ^ block[c], 7);
        // dfmt on

        return block;
    }

    unittest {
        ///Standards: RFC 7539
        /// Section 2.2.1

        uint[16] testBlock = [
            0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
            0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
            0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
            0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320
        ];

        uint[16] resultBlock = [
            0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
            0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
            0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
            0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320
        ];

        assert(quarterRound(testBlock, 2, 7, 8, 13) == resultBlock, "Quarter Round failed");
    }

    private static uint[16] innerRound(return ref uint[16] block) pure {
        foreach (_; 0 .. 10) {
            quarterRound(block, 0, 4, 8, 12);
            quarterRound(block, 1, 5, 9, 13);
            quarterRound(block, 2, 6, 10, 14);
            quarterRound(block, 3, 7, 11, 15);

            quarterRound(block, 0, 5, 10, 15);
            quarterRound(block, 1, 6, 11, 12);
            quarterRound(block, 2, 7, 8, 13);
            quarterRound(block, 3, 4, 9, 14);
        }

        return block;
    }

    private static uint[16] block(return ref uint[16] block) pure {
        immutable(uint[16]) savedBlock = block;

        innerRound(block);
        block[] += savedBlock[];

        return block;
    }

    unittest {
        ///Standards: RFC 7539
        /// Section 2.3.2

        uint[16] initialState = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
            0x00000001, 0x09000000, 0x4a000000, 0x00000000
        ];

        uint[16] secondInitialState = initialState.dup;

        uint[16] expectedIntermediateState = [
            0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f,
            0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7,
            0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd,
            0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2
        ];

        uint[16] expectedFinalState = [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
            0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
            0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
            0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2
        ];

        assert(innerRound(initialState) == expectedIntermediateState, "Inner Round failed");
        assert(block(secondInitialState) == expectedFinalState, "Block failed");
    }

    unittest {
        ///Standards: RFC 7539
        /// Section: 2.4.2

        State testBlockState1;

        ubyte[32] key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        ];

        ubyte[12] nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00
        ];

        testBlockState1.key = key;
        testBlockState1.nonce = nonce;
        testBlockState1.counter = 1;
        State testBlockState2 = testBlockState1;
        testBlockState2.counter = 2;

        uint[16] estimatedFirstTestBlock = [
            0xf3514f22, 0xe1d91b40, 0x6f27de2f, 0xed1d63b8,
            0x821f138c, 0xe2062c3d, 0xecca4f7e, 0x78cff39e,
            0xa30a3b8a, 0x920a6072, 0xcd7479b5, 0x34932bed,
            0x40ba4c79, 0xcd343ec6, 0x4c2c21ea, 0xb7417df0
        ];

        uint[16] estimatedSecondTestBlock = [
            0x9f74a669, 0x410f633f, 0x28feca22, 0x7ec44dec,
            0x6d34d426, 0x738cb970, 0x3ac5e9f3, 0x45590cc4,
            0xda6e8b39, 0x892c831a, 0xcdea67c1, 0x2b7e1d90,
            0x037463f3, 0xa11a2073, 0xe8bcfb88, 0xedc49139
        ];

        assert(block(testBlockState1.asInts) == estimatedFirstTestBlock, "First test block() failed");
        assert(block(testBlockState2.asInts) == estimatedSecondTestBlock, "Second test block() failed");
    }
}

unittest {
    ///Standards: RFC 7539
    /// Section 2.4.2

    ubyte[32] key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    ];

    ubyte[12] nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    ];

    ubyte[] originalText = cast(ubyte[])(
        "Ladies and Gentlemen of the class of '99: If I could offer you only" ~
            " one tip for the future, sunscreen would be it."
    ).dup;

    ubyte[] estimatedDecryptedText = originalText;

    ubyte[114] estimatedData = [
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
        0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
        0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
        0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
        0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d
    ];

    Chacha encryptor = Chacha(key, nonce, 1);
    encryptor.crypt(originalText);

    assert(originalText == estimatedData, "Final encryption failure");

    Chacha decryptor = Chacha(key, nonce, 1);
    decryptor.crypt(originalText);

    assert(originalText == estimatedDecryptedText, "Decryption failed");
}
