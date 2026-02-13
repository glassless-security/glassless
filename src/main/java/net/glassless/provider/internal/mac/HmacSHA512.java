package net.glassless.provider.internal.mac;

public class HmacSHA512 extends AbstractHmac {
    public HmacSHA512() {
        super("SHA512", 64);
    }
}
