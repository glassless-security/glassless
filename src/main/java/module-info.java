module net.glassless.provider {
   requires com.dylibso.chicory.runtime;
   requires com.dylibso.chicory.wasm;
   requires com.dylibso.chicory.annotations;
   requires static java.compiler;
   requires com.dylibso.chicory.wasi;

   exports net.glassless.provider;
   opens net.glassless.provider.internal.cipher to java.base;
   opens net.glassless.provider.internal.digest to java.base;
   opens net.glassless.provider.internal.mac to java.base;
   opens net.glassless.provider.internal.keygen to java.base;
   opens net.glassless.provider.internal.signature to java.base;
   opens net.glassless.provider.internal.keypairgen to java.base;
   opens net.glassless.provider.internal.secretkeyfactory to java.base;
   opens net.glassless.provider.internal.keyfactory to java.base;
   opens net.glassless.provider.internal.keyagreement to java.base;
   opens net.glassless.provider.internal.algparams to java.base;
   opens net.glassless.provider.internal.securerandom to java.base;
   opens net.glassless.provider.internal.algparamgen to java.base;
   opens net.glassless.provider.internal.kdf to java.base;
   opens net.glassless.provider.internal.eddsa to java.base;
   opens net.glassless.provider.internal.xdh to java.base;
   opens net.glassless.provider.internal.mlkem to java.base;
   opens net.glassless.provider.internal.mldsa to java.base;
   opens net.glassless.provider.internal.slhdsa to java.base;
   opens net.glassless.provider.internal.hybridkem to java.base;

   provides java.security.Provider with net.glassless.provider.GlaSSLessProvider;
}
