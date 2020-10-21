package SHA3;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.binary.Hex;

public class Main {
    public static void main(String[] args) throws IOException {

        String message = "A tie vtáky z toho tŕnia, štrng-brng do druhého tŕnia.";
        byte[] bytes   = message.getBytes(StandardCharsets.UTF_8);
        Keccak keccak  = new Keccak();
        byte[] hash    = keccak.sponge(bytes);

        System.out.println(message);
        System.out.println();
        System.out.println(Hex.encodeHex(hash));

    }
}
