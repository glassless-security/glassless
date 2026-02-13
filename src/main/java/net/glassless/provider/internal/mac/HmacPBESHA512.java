package net.glassless.provider.internal.mac;

public class HmacPBESHA512 extends AbstractHmacPBE {
    public HmacPBESHA512() {
        super("SHA512", "SHA512", 64, 64);
    }
}
