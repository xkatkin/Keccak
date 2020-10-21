package SHA3;

import java.util.stream.IntStream;

public class Util {
    public static byte[] longToByte(long variable) {
        return new byte[] {
                (byte) variable,
                (byte) (variable >> 8),
                (byte) (variable >> 16),
                (byte) (variable >> 24),
                (byte) (variable >> 32),
                (byte) (variable >> 40),
                (byte) (variable >> 48),
                (byte) (variable >> 56)};
    }

    public static long byteToLong(byte[] array) {
        return  ((long) array[7] << 56)
                | ((long) array[6] & 0xff) << 48
                | ((long) array[5] & 0xff) << 40
                | ((long) array[4] & 0xff) << 32
                | ((long) array[3] & 0xff) << 24
                | ((long) array[2] & 0xff) << 16
                | ((long) array[1] & 0xff) << 8
                | ((long) array[0] & 0xff);
    }

    public static byte[] negate(byte[] array) {
        IntStream
                .range(0, array.length)
                .parallel()
                .forEach(index -> array[index] = (byte) ~array[index]);
        return array;
    }

    public static byte[] and(byte[] first, byte[] second) {
        IntStream
                .range(0, first.length)
                .parallel()
                .forEach(index -> first[index] &= second[index]);
        return first;
    }

    public static byte[] xor(byte[] first, byte[] second) {
        return xor(first, second, first.length);
    }

    public static byte[] xor(byte[] first, byte[] second, int length) {
        IntStream
                .range(0, length)
                .parallel()
                .forEach(index -> first[index] ^= second[index]);
        return first;
    }

    public static byte[] rotateLeft(byte[] array, int count) {
        return longToByte(Long.rotateLeft(byteToLong(array), count));
    }



}
