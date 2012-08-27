// Copyright (C) 2011 - Will Glozer.  All rights reserved.

package com.lambdaworks.crypto;

import static java.lang.Integer.MAX_VALUE;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.lambdaworks.jni.LibraryLoader;
import com.lambdaworks.jni.LibraryLoaders;

/**
 * An implementation of the <a href="http://www.tarsnap.com/scrypt/scrypt.pdf"/>scrypt</a>
 * key derivation function. This class will attempt to load a native library
 * containing the optimized C implementation from
 * <a href="http://www.tarsnap.com/scrypt.html">http://www.tarsnap.com/scrypt.html<a> and
 * fall back to the pure Java version if that fails.
 *
 * @author  Will Glozer
 */
public class SCrypt {
    private static final boolean native_library_loaded;

    static {
        LibraryLoader loader = LibraryLoaders.loader();
        final String nativeRequirement = System.getProperty("scrypt.native");
        boolean tryLoad = true;
        boolean requireLoad = false;
        if (null != nativeRequirement) {
            if ("false".equalsIgnoreCase(nativeRequirement)) {
                tryLoad = false;
            } else if ("require".equalsIgnoreCase(nativeRequirement)) {
                requireLoad = true;
            } else if (!"default".equalsIgnoreCase(nativeRequirement)) {
                throw new IllegalArgumentException("Unrecognised scrypt.native, " +
                        "expecting false, require or default; not " + nativeRequirement);
            }
        }

        if (tryLoad) {
            native_library_loaded = loader.load("scrypt", true);
            if (requireLoad && !native_library_loaded) {
                throw new IllegalStateException("native scrypt library failed to load");
            }
        } else {
            native_library_loaded = false;
        }
    }

    /**
     * Implementation of the <a href="http://www.tarsnap.com/scrypt/scrypt.pdf"/>scrypt KDF</a>.
     * Calls the native implementation {@link #scryptN} when the native library was successfully
     * loaded, otherwise calls {@link #scryptJ}.
     *
     * @param passwd    Password.
     * @param salt      Salt.
     * @param N         CPU cost parameter.
     * @param r         Memory cost parameter.
     * @param p         Parallelization parameter.
     * @param dkLen     Intended length of the derived key.
     *
     * @return The derived key.
     *
     * @throws GeneralSecurityException when HMAC_SHA256 is not available.
     */
    public static byte[] scrypt(byte[] passwd, byte[] salt, int N, int r, int p, int dkLen) throws GeneralSecurityException {
        return native_library_loaded ? scryptN(passwd, salt, N, r, p, dkLen) : scryptJ(passwd, salt, N, r, p, dkLen);
    }

    /**
     * Native C implementation of the <a href="http://www.tarsnap.com/scrypt/scrypt.pdf"/>scrypt KDF</a> using
     * the code from <a href="http://www.tarsnap.com/scrypt.html">http://www.tarsnap.com/scrypt.html<a>.
     *
     * @param passwd    Password.
     * @param salt      Salt.
     * @param N         CPU cost parameter.
     * @param r         Memory cost parameter.
     * @param p         Parallelization parameter.
     * @param dkLen     Intended length of the derived key.
     *
     * @return The derived key.
     */
    public static native byte[] scryptN(byte[] passwd, byte[] salt, int N, int r, int p, int dkLen);

    /**
     * Pure Java implementation of the <a href="http://www.tarsnap.com/scrypt/scrypt.pdf"/>scrypt KDF</a>.
     *
     * @param passwd    Password.
     * @param salt      Salt.
     * @param N         CPU cost parameter.
     * @param r         Memory cost parameter.
     * @param p         Parallelization parameter.
     * @param dkLen     Intended length of the derived key.
     *
     * @return The derived key.
     *
     * @throws GeneralSecurityException when HMAC_SHA256 is not available.
     */
    public static byte[] scryptJ(byte[] passwd, byte[] salt, int N, int r, int p, int dkLen) throws GeneralSecurityException {
        if (N < 2 || (N & (N - 1)) != 0) throw new IllegalArgumentException("N must be a power of 2 greater than 1");

        if (N > MAX_VALUE / 128 / r) throw new IllegalArgumentException("Parameter N is too large");
        if (r > MAX_VALUE / 128 / p) throw new IllegalArgumentException("Parameter r is too large");

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(passwd, "HmacSHA256"));

        byte[] DK = new byte[dkLen];

        byte[] B  = new byte[128 * r * p];
        int x[]  = new int[16];
        ByteBuffer XY = bb(256 * r);
        ByteBuffer V  = bb(128 * r * N);
        ByteBuffer X  = bb(64);
        int i;

        PBKDF.pbkdf2(mac, salt, 1, B, p * 128 * r);

        for (i = 0; i < p; i++) {
            smix(B, i * 128 * r, r, N, V, XY, X, x);
        }

        PBKDF.pbkdf2(mac, B, 1, DK, dkLen);

        return DK;
    }

    public static void smix(byte[] B, int Bi, int r, int N, ByteBuffer V, ByteBuffer XY, ByteBuffer X, int[] x) {
        int Xi = 0;
        int Yi = 128 * r;
        int i;

        arraycopy(B, Bi, XY, Xi, 128 * r);

        for (i = 0; i < N; i++) {
            arraycopy(XY, Xi, V, i * (128 * r), 128 * r);
            blockmix_salsa8(XY, Xi, Yi, r, X, x);
        }

        LongBuffer sl = V.asLongBuffer();
        LongBuffer dl = XY.asLongBuffer();
        for (i = 0; i < N; i++) {
            int j = integerify(XY, Xi, r) & (N - 1);
            for (int k = 0; k < 128 * r / 8; k++) {
                dl.put(Xi/8 + k, (dl.get(Xi/8 + k) ^ sl.get(j * (128 * r)/8 + k)));
            }
            blockmix_salsa8(XY, Xi, Yi, r, X, x);
        }

        arraycopy(XY, Xi, B, Bi, 128 * r);
    }

    private static void arraycopy(byte[] src, int srcPos, byte[] dest, int destPos, int len) {
        System.arraycopy(src, srcPos, dest, destPos, len);
    }

    private static void arraycopy(ByteBuffer src, int srcPos, byte[] dest, int destPos, int len) {
        src.position(srcPos);
        src.get(dest, destPos, len);
        src.rewind();
    }

    private static void arraycopy(byte[] src, int srcPos, ByteBuffer dest, int destPos, int len) {
        for (int i = 0; i < len; ++i)
            dest.put(i + destPos, src[srcPos + i]);
        dest.rewind();
    }

    static void arraycopy(ByteBuffer src, int srcPos, ByteBuffer dst, int dstPos, int length) {
        src.position(srcPos);
        ByteBuffer dup = src.duplicate();
        dup.limit(srcPos + length);
        dst.position(dstPos);
        dst.put(dup);
        src.rewind();
        dst.rewind();
    }

    public static void blockmix_salsa8(ByteBuffer BY, int Bi, int Yi, int r, ByteBuffer X, int[] x) {
        int i;

        arraycopy(BY, Bi + (2 * r - 1) * 64, X, 0, 64);

        LongBuffer byl = BY.asLongBuffer();
        LongBuffer xl = X.asLongBuffer();
        for (i = 0; i < 2 * r; i++) {
            xl.put(0, xl.get(0) ^ byl.get(i*8 + 0));
            xl.put(1, xl.get(1) ^ byl.get(i*8 + 1));
            xl.put(2, xl.get(2) ^ byl.get(i*8 + 2));
            xl.put(3, xl.get(3) ^ byl.get(i*8 + 3));
            xl.put(4, xl.get(4) ^ byl.get(i*8 + 4));
            xl.put(5, xl.get(5) ^ byl.get(i*8 + 5));
            xl.put(6, xl.get(6) ^ byl.get(i*8 + 6));
            xl.put(7, xl.get(7) ^ byl.get(i*8 + 7));
            salsa20_8(X, x);
            arraycopy(X, 0, BY, Yi + (i * 64), 64);
        }

        for (i = 0; i < r; i++) {
            arraycopy(BY, Yi + (i * 2) * 64, BY, Bi + (i * 64), 64);
        }

        for (i = 0; i < r; i++) {
            arraycopy(BY, Yi + (i * 2 + 1) * 64, BY, Bi + (i + r) * 64, 64);
        }
    }

    public static int R(int a, int b) {
        return (a << b) | (a >>> (32 - b));
    }

    public static void salsa20_8(ByteBuffer B, int[] x) {
        int i;

        IntBuffer B32 = B.asIntBuffer();

        B32.get(x);

        for (i = 8; i > 0; i -= 2) {
            x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
            x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
            x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
            x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
            x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
            x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
            x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
            x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
            x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
            x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
            x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
            x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
            x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
            x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
            x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
            x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
        }

        for (i = 0; i < 16; ++i) B32.put(i, x[i] + B32.get(i));
    }

    public static int integerify(ByteBuffer B, int Bi, int r) {
        Bi += (2 * r - 1) * 64;
        return B.getInt(Bi);
    }

    private static ByteBuffer bb(int len) {
        final ByteBuffer X = ByteBuffer.allocateDirect(len);
        X.order(ByteOrder.LITTLE_ENDIAN);
        return X;
    }
}
