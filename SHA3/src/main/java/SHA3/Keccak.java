package SHA3;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.function.Function;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static SHA3.Util.and;
import static SHA3.Util.xor;
import static SHA3.Util.negate;
import static SHA3.Util.longToByte;
import static SHA3.Util.rotateLeft;


public class Keccak {
    //parameters for SHA3-256
    private static final int c = 512;      //capacity
    private static final int r = 1600 - c; //bitrate
    private static final int d = c / 2;    //output block size

    //Keccak
    private byte[][][] iota(byte[][][] stateMemoryCube, final int[] lsfr) {
        IntStream
                .range(0, 7)
                .forEach(i -> {
                    lsfr[0] = ((lsfr[0] << 1) ^ ((lsfr[0] >> 7) * 0x71)) % 256;
                    int pos = (1 << i) - 1;
                    if ((lsfr[0] & 2) != 0) {
                        System.arraycopy(xor(stateMemoryCube[0][0], longToByte(1L << pos)) , 0, stateMemoryCube[0][0], 0, 8);
                    }
                });
        return stateMemoryCube;
    }

    private byte[][][] chi(byte[][][] stateMemoryCube) {
        IntStream
                .range(0, 5)
                .forEach(j -> {
                    byte[][] sheet = Arrays
                            .stream(stateMemoryCube)
                            .map(x -> x[j])
                            .toArray(byte[][]::new);
                    IntStream
                            .range(0, 5)
                            .forEach(i -> stateMemoryCube[i][j] = xor(sheet[i], and(negate(sheet[(i + 1) % 5]), sheet[(i + 2) % 5])));
                });
        return stateMemoryCube;
    }

    private byte[][][] roAndPi(byte[][][] stateMemoryCube) {
        class roContext { //wrapper class for final values
            public int x = 1;
            public int y = 0;
            public byte[] current = stateMemoryCube[x][y];
        }
        final roContext context = new roContext();

        IntStream
                .range(0, 24)
                .forEach(index -> {
                    int tempX = context.x;
                    context.x = context.y;
                    context.y = (2 * tempX + 3 * context.y) % 5;

                    byte[] shiftArray= context.current;
                    context.current = stateMemoryCube[context.x][context.y];

                    stateMemoryCube[context.x][context.y] = rotateLeft(shiftArray, (index + 1) * (index + 2) / 2);
                });
        return stateMemoryCube;
    }

    private byte[][][] theta(byte[][][] stateMemoryCube) {
        //count parity
        byte[][] parity = IntStream
                .range(0, 5)
                .mapToObj(index -> Arrays
                        .stream(stateMemoryCube[index])
                        .reduce(new byte[8], Util::xor)
                )
                .toArray(byte[][]::new);

        byte[][] shifted = IntStream
                .range(0, 5)
                .mapToObj(index -> rotateLeft(parity[index], 1))
                .toArray(byte[][]::new);

        //add parity
        IntStream
                .range(0, 5)
                .forEach(x -> stateMemoryCube[x] = Arrays
                        .stream(stateMemoryCube[x])
                        .map(yArray -> xor(yArray, xor(parity[(x + 4) % 5], shifted[(x + 1) % 5])))
                        .toArray(byte[][]::new)
                );
        return stateMemoryCube;
    }

    private byte[][][] constructCube(byte[] stateMemory) {
        byte[][] builtMemory = IntStream
                .range(0, 25)
                .parallel()
                .mapToObj(index -> Arrays.copyOfRange(stateMemory, index * 8, index * 8 + 8))
                .toArray(byte[][]::new);
        return IntStream
                .range(0, 5)
                .parallel()
                .mapToObj(index -> Arrays.copyOfRange(builtMemory, index * 5, index * 5 + 5))
                .toArray(byte[][][]::new);
    }

    private byte[] deconstructCube(byte[][][] stateMemoryCube) {
        byte[] stateMemory = new byte[(r+c)/8];
        byte[][] flattenedCube = Arrays
                .stream(stateMemoryCube)
                .parallel()
                .flatMap(Arrays::stream)
                .toArray(byte[][]::new);
        IntStream
                .range(0, flattenedCube.length)
                .parallel()
                .forEach(index -> System.arraycopy(flattenedCube[index], 0, stateMemory, 8 * index, 8));
        return stateMemory;
    }

    private byte[] fPermutate(byte[] stateMemory) {
        //fill
        final byte[][][][] stateMemoryCube = {constructCube(stateMemory)};
        final int[] lfsr = {1}; //linear feedback shift register

        Function<byte[][][], byte[][][]> iota    = state -> iota(state, lfsr);
        Function<byte[][][], byte[][][]> chi     = this::chi;
        Function<byte[][][], byte[][][]> roAndPi = this::roAndPi;
        Function<byte[][][], byte[][][]> theta   = this::theta;

        //permutate
        IntStream
                .range(0, 24)
                .forEach(i -> stateMemoryCube[0] = theta
                        .andThen(roAndPi)
                        .andThen(chi)
                        .andThen(iota)
                        .apply(stateMemoryCube[0]));

        //flatten
        return deconstructCube(stateMemoryCube[0]);
    }

    public byte[] sponge(final byte[] message) throws IOException {
        //variable representing state memory
        byte[] stateMemory = new byte[(r+c)/8];

        //padding phase 
        int paddedLength =
                message.length % r == 0 ?
                message.length :
                message.length + r - (message.length % r);
        byte[] paddedMessage = Arrays.copyOf(message, paddedLength);

        if(paddedLength > message.length) {
            paddedMessage[message.length]   = (byte) 0x06;
            paddedMessage[paddedLength - 1] = (byte) 0x80;
        }

        //split message into blocks of r
        byte[][] splitMessage = IntStream
                .range(0, paddedLength / r)
                .parallel()
                .mapToObj(index -> Arrays.copyOfRange(paddedMessage, r * index , r + r * index))
                .toArray(byte[][]::new);

        //absorbing phase
        stateMemory = Stream
                .of(splitMessage)
                .reduce(stateMemory, (sponge, messageBlock) -> fPermutate(xor(sponge,messageBlock, r / 8)));

        //squeeze
        int counter = 0;
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        while(counter < d / 8) {
            result.write(Arrays.copyOfRange(stateMemory, 0, r / 8));
            stateMemory = fPermutate(stateMemory);
            counter += r / 8;
        }

        //truncate
        return Arrays.copyOfRange(result.toByteArray(), 0, d / 8);

    }
}