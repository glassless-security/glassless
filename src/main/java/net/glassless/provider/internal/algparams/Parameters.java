package net.glassless.provider.internal.algparams;

import java.io.IOException;
import java.math.BigInteger;

final class Parameters {
    static int readLength(byte[] der, int[] offset) {
        int b = der[offset[0]++] & 0xFF;
        if (b < 128) {
            return b;
        }
        int numBytes = b & 0x7F;
        int length = 0;
        for (int i = 0; i < numBytes; i++) {
            length = (length << 8) | (der[offset[0]++] & 0xFF);
        }
        return length;
    }

    static byte[] encodeSequence(byte[] ivEncoded, byte[] tLenEncoded) {
        int contentLen = ivEncoded.length + tLenEncoded.length;
        byte[] result = new byte[2 + contentLen];
        result[0] = 0x30;
        result[1] = (byte) contentLen;
        System.arraycopy(ivEncoded, 0, result, 2, ivEncoded.length);
        System.arraycopy(tLenEncoded, 0, result, 2 + ivEncoded.length, tLenEncoded.length);

        return result;
    }

    static BigInteger readInteger(byte[] der, int[] offset) throws IOException {
        if (der[offset[0]++] != 0x02) {
            throw new IOException("Expected INTEGER tag");
        }
        int len = readLength(der, offset);
        byte[] intBytes = new byte[len];
        System.arraycopy(der, offset[0], intBytes, 0, len);
        offset[0] += len;
        return new BigInteger(intBytes);
    }

    static byte[] encodeLength(int length) {
        if (length < 128) {
            return new byte[]{(byte) length};
        } else if (length < 256) {
            return new byte[]{(byte) 0x81, (byte) length};
        } else if (length < 65536) {
            return new byte[]{(byte) 0x82, (byte) (length >> 8), (byte) length};
        } else {
            return new byte[]{(byte) 0x83, (byte) (length >> 16), (byte) (length >> 8), (byte) length};
        }
    }
}
