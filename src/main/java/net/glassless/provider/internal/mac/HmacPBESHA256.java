package net.glassless.provider.internal.mac;

public class HmacPBESHA256 extends AbstractHmacPBE {
    public HmacPBESHA256() {
        super("SHA256", "SHA256", 32, 32);
    }
}
