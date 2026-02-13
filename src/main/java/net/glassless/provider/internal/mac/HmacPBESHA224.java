package net.glassless.provider.internal.mac;

public class HmacPBESHA224 extends AbstractHmacPBE {
    public HmacPBESHA224() {
        super("SHA224", "SHA224", 28, 28);
    }
}
