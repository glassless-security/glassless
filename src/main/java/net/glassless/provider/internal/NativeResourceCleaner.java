package net.glassless.provider.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.ref.Cleaner;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility for cleaning up native OpenSSL resources when objects are garbage collected.
 * Provides a shared Cleaner instance and helper methods to register cleanup actions.
 */
public final class NativeResourceCleaner {

   private static final Cleaner CLEANER = Cleaner.create();

   private NativeResourceCleaner() {
      // Utility class
   }

   /**
    * Holder for mutable native resources that need cleanup.
    * The Cleaner references this holder, and the holder's fields can be updated
    * as resources are allocated/freed during the object's lifetime.
    */
   public static class ResourceHolder implements Runnable {
      private volatile MemorySegment evpMdCtx;
      private volatile MemorySegment evpCipherCtx;
      private volatile MemorySegment evpPkey;
      private volatile Arena arena;

      public void setEvpMdCtx(MemorySegment ctx) {
         this.evpMdCtx = ctx;
      }

      public void setEvpCipherCtx(MemorySegment ctx) {
         this.evpCipherCtx = ctx;
      }

      public void setEvpPkey(MemorySegment pkey) {
         this.evpPkey = pkey;
      }

      public void setArena(Arena arena) {
         this.arena = arena;
      }

      public void clearEvpMdCtx() {
         this.evpMdCtx = null;
      }

      public void clearEvpCipherCtx() {
         this.evpCipherCtx = null;
      }

      public void clearEvpPkey() {
         this.evpPkey = null;
      }

      @Override
      public void run() {
         // Free EVP contexts
         if (evpMdCtx != null && !evpMdCtx.equals(MemorySegment.NULL)) {
            try {
               OpenSSLCrypto.EVP_MD_CTX_free(evpMdCtx);
            } catch (Throwable e) {
               // Ignore
            }
         }
         if (evpCipherCtx != null && !evpCipherCtx.equals(MemorySegment.NULL)) {
            try {
               OpenSSLCrypto.EVP_CIPHER_CTX_free(evpCipherCtx);
            } catch (Throwable e) {
               // Ignore
            }
         }
         if (evpPkey != null && !evpPkey.equals(MemorySegment.NULL)) {
            try {
               OpenSSLCrypto.EVP_PKEY_free(evpPkey);
            } catch (Throwable e) {
               // Ignore
            }
         }
         // Close arena last
         if (arena != null) {
            try {
               arena.close();
            } catch (Throwable e) {
               // Ignore
            }
         }
      }
   }

   /**
    * Creates a new resource holder and registers it for cleanup when the given object is GC'd.
    *
    * @param obj the object to monitor for garbage collection
    * @return the holder that can be updated with resources to clean
    */
   public static ResourceHolder createHolder(Object obj) {
      ResourceHolder holder = new ResourceHolder();
      CLEANER.register(obj, holder);
      return holder;
   }

   /**
    * Registers a cleanup action that will be executed when the given object is garbage collected.
    *
    * @param obj the object to monitor for garbage collection
    * @param action the cleanup action to run
    * @return a Cleaner.Cleanable that can be used to clean up early if desired
    */
   public static Cleaner.Cleanable register(Object obj, Runnable action) {
      return CLEANER.register(obj, action);
   }

   /**
    * Builder for creating cleanup actions that free multiple native resources.
    */
   public static class CleanupBuilder {
      private final List<Runnable> actions = new ArrayList<>();
      private Arena arena;

      /**
       * Adds an EVP_MD_CTX to be freed.
       */
      public CleanupBuilder freeEvpMdCtx(MemorySegment ctx) {
         if (ctx != null && !ctx.equals(MemorySegment.NULL)) {
            actions.add(() -> {
               try {
                  OpenSSLCrypto.EVP_MD_CTX_free(ctx);
               } catch (Throwable e) {
                  // Ignore cleanup errors
               }
            });
         }
         return this;
      }

      /**
       * Adds an EVP_CIPHER_CTX to be freed.
       */
      public CleanupBuilder freeEvpCipherCtx(MemorySegment ctx) {
         if (ctx != null && !ctx.equals(MemorySegment.NULL)) {
            actions.add(() -> {
               try {
                  OpenSSLCrypto.EVP_CIPHER_CTX_free(ctx);
               } catch (Throwable e) {
                  // Ignore cleanup errors
               }
            });
         }
         return this;
      }

      /**
       * Adds an EVP_PKEY to be freed.
       */
      public CleanupBuilder freeEvpPkey(MemorySegment pkey) {
         if (pkey != null && !pkey.equals(MemorySegment.NULL)) {
            actions.add(() -> {
               try {
                  OpenSSLCrypto.EVP_PKEY_free(pkey);
               } catch (Throwable e) {
                  // Ignore cleanup errors
               }
            });
         }
         return this;
      }

      /**
       * Adds an Arena to be closed.
       */
      public CleanupBuilder closeArena(Arena arena) {
         this.arena = arena;
         return this;
      }

      /**
       * Builds the cleanup action.
       */
      public Runnable build() {
         // Capture the current state
         final List<Runnable> cleanupActions = new ArrayList<>(actions);
         final Arena arenaToClose = arena;

         return () -> {
            // Free native resources first
            for (Runnable action : cleanupActions) {
               action.run();
            }
            // Close arena last
            if (arenaToClose != null) {
               try {
                  arenaToClose.close();
               } catch (Throwable e) {
                  // Ignore cleanup errors
               }
            }
         };
      }

      /**
       * Registers the cleanup action for the given object.
       */
      public Cleaner.Cleanable registerFor(Object obj) {
         return NativeResourceCleaner.register(obj, build());
      }
   }

   /**
    * Creates a new cleanup builder.
    */
   public static CleanupBuilder builder() {
      return new CleanupBuilder();
   }
}
