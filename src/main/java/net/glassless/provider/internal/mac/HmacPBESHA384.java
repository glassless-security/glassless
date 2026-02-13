package net.glassless.provider.internal.mac;

public class HmacPBESHA384 extends AbstractHmacPBE {
    public HmacPBESHA384() {
        super("SHA384", "SHA384", 48, 48);
    }
}
