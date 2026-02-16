package net.glassless.provider.internal;

import java.util.List;

import com.dylibso.chicory.annotations.WasmModuleInterface;
import com.dylibso.chicory.runtime.HostFunction;
import com.dylibso.chicory.runtime.ImportValues;
import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.runtime.Memory;
import com.dylibso.chicory.wasi.WasiOptions;
import com.dylibso.chicory.wasi.WasiPreview1;
import com.dylibso.chicory.wasm.types.ValType;

@WasmModuleInterface(WasmResource.absoluteFile)
public class OpenSSLCryptoModule implements AutoCloseable {
   private static OpenSSLCryptoModule INSTANCE;

   private final Instance instance;
   private final WasiPreview1 wasi;
   private final OpenSSLCryptoModule_ModuleExports exports;

   private OpenSSLCryptoModule() {
      wasi = WasiPreview1.builder()
         .withOptions(WasiOptions.builder().build())
         .build();
      instance = Instance.builder(OpenSSLModule.load())
         .withMachineFactory(OpenSSLModule::create)
         .withImportValues(ImportValues.builder()
            .addFunction(wasi.toHostFunctions())
            .addFunction(new HostFunction("env", "getpid",
               List.of(), List.of(ValType.I32),
               (inst, args) -> new long[] { 1 }))
            .build())
         .build();
      exports = new OpenSSLCryptoModule_ModuleExports(instance);
      exports._initialize();
   }

   public static synchronized OpenSSLCryptoModule getInstance() {
      if (INSTANCE == null) {
         INSTANCE = new OpenSSLCryptoModule();
      }
      return INSTANCE;
   }

   public OpenSSLCryptoModule_ModuleExports exports() {
      return exports;
   }

   public Memory memory() {
      return exports.memory();
   }

   @Override
   public void close() {
      if (wasi != null) {
         wasi.close();
      }
   }
}
