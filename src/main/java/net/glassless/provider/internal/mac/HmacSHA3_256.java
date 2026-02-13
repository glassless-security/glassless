package net.glassless.provider.internal.mac;

public class HmacSHA3_256 extends AbstractHmac {
    public HmacSHA3_256() {
        super("SHA3-256", 32);
    }
}
