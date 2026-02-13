package net.glassless.provider.internal.mac;

public class HmacPBESHA1 extends AbstractHmacPBE {
    public HmacPBESHA1() {
        super("SHA1", "SHA1", 20, 20);
    }
}
