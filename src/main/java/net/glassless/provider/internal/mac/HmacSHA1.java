package net.glassless.provider.internal.mac;

public class HmacSHA1 extends AbstractHmac {
    public HmacSHA1() {
        super("SHA1", 20);
    }
}
