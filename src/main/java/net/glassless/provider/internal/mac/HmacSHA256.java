package net.glassless.provider.internal.mac;

public class HmacSHA256 extends AbstractHmac {
    public HmacSHA256() {
        super("SHA256", 32);
    }
}
