package com.lambdaworks.crypto;

import java.security.GeneralSecurityException;

public class Benchmark {
    static interface Block {
        void run() throws Exception;
    }

    static class Timer {
        final long start = System.nanoTime();
        void print() {
            System.out.println((System.nanoTime() - start) / 1e9);
        }
    }
    
    public static void main(String[] args) throws Exception {
        System.out.println("java:");
        final int runs = 5;
        for (int i = 0; i < runs; ++i) {
            time(new Block() {
                public void run() throws Exception {
                    runJava();                    
                }
            });
        }
        
        System.out.println("native:");
        for (int i = 0; i < runs; ++i) {
            time(new Block() {
                public void run() throws Exception {
                    runNative();                    
                }
            });
        }
    }

    private static void runNative() throws Exception {
        lots(new Block() {
            public void run() throws GeneralSecurityException {
                SCrypt.scryptN(new byte[16], new byte[16], 16384, 8, 1, 32);
            }
        });
    }

    private static void runJava() throws Exception {
        lots(new Block() {
            public void run() throws GeneralSecurityException {
                SCrypt.scryptJ(new byte[16], new byte[16], 16384, 8, 1, 32);
            }
        });
    }

    private static void lots(Block block) throws Exception {
        for (int i = 0; i < 50; ++i) {
            block.run();
        }
    }
    
    private static void time(Block block) throws Exception {
        final Timer t = new Timer();
        block.run();
        t.print();
    }
    
    String s() [] {
        return new String[0];
    }
}
