package main;

import java.nio.charset.StandardCharsets;

public class main {

    public static BlockCipher getCipherName(String name) {
        AESEngine engine = new AESEngine();

        switch (name) {
            case "CBC":
                return new CBCBlockCipher(engine);
            case "ECB":
            case "normal":
                return engine;
            case "":
                return null;
            default:
                return null;
        }
    }

    public static void main(String[] args) {
        new main().run();
    }

    void run() {
        byte[] key =  new byte[] {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        byte[] dat =  "pham hieu dep trai vo dich".getBytes(StandardCharsets.UTF_8);
        byte[] iv =  new byte[] {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        String mode = "CBC";
        byte[] output = encryptMode(mode, dat, key, iv);
        decryptMode(mode, output, key, iv);
    }

    byte[] encryptMode(String mode, byte[] dat, byte[] key, byte[] iv) {
        System.out.println("===== Mã hóa "+mode+" =====");
        PKCS7Padding padding = new PKCS7Padding();
        BlockCipher block = getCipherName(mode);
        block.init(true, iv, key);
        int length = block.getBlockSize() - (dat.length % block.getBlockSize());
        int dataSize = length + dat.length;
        byte[] out = new byte[dataSize];
        //tg bat dau ma hoa
        long startTime = System.nanoTime();
        byte[] paddingData = new byte[dataSize];
        System.arraycopy(dat, 0, paddingData,0, dat.length);
        padding.addPadding(paddingData,  dat.length);
        int count = paddingData.length / block.getBlockSize();
        for (int i = 0; i < count ; i++) {
            block.processBlock(paddingData,i * block.getBlockSize(),out,i * block.getBlockSize());
        }
        //ket thuc ma hoa
        long durationEncTime = System.nanoTime() - startTime;
        System.out.println("[-] Duration encrypt: " + durationEncTime +" nano second");

        System.out.print("[.] Padding data : 0x");
        for (int i = 0 ;i < paddingData.length ;i ++) {
            System.out.format("%02x",paddingData[i]);
        }

        System.out.print("\n[.] Encrypt data output: 0x");
        for (int i = 0 ;i < out.length ;i ++) {
            System.out.format("%02x",out[i]);
        }
        System.out.println("\n");
        return out;
    }

    byte[] decryptMode(String mode, byte[] dat, byte[] key, byte[] iv) {
        System.out.println("===== Giải mã "+mode+" =====");
        PKCS7Padding padding = new PKCS7Padding();
        BlockCipher block = getCipherName(mode);
        block.init(false, iv, key);
        int dataSize = dat.length ;
        byte [] decrypt =  new byte[dataSize];
        int count = dataSize / block.getBlockSize();
        //tg bat dau giai ma~
        long startTime = System.nanoTime();
        for (int i = 0; i < count ; i++) {
            block.processBlock(dat,i * block.getBlockSize(),decrypt,i * block.getBlockSize());
        }

//        engine.processBlock(out,0,decrypt,0);
        int paddingCount = padding.padCount(decrypt);
        byte[] decryptResult = new byte[decrypt.length - paddingCount];
        System.arraycopy(decrypt, 0, decryptResult, 0, decryptResult.length);
        long durationDecTime = System.nanoTime() - startTime;
        System.out.print("[-] Duration decrypt: " + durationDecTime +" nano second");
        System.out.print("\n[.] Decrypt data output: 0x");
        for (int i = 0 ;i < decryptResult.length ;i ++) {
            System.out.format("%02x",decryptResult[i]);
        }
        System.out.println("\n[.] String result: " +new String(decryptResult));
        return decryptResult;
    }

//    public byte[] encryptCBC(byte[] dat, byte[] key, byte[] iv) {
//
//        System.out.println("===== Mã hóa CBC =====");
//
//        AESEngine engine = new AESEngine();
//        PKCS7Padding padding = new PKCS7Padding();
//        CBCBlockCipher block = new CBCBlockCipher(engine);
//        block.init(true, iv, key);
//
//        int length = engine.getBlockSize() - (dat.length % engine.getBlockSize());
//        int dataSize = length + dat.length;
//
//        byte[] out = new byte[dataSize];
//
//        //tg bat dau ma hoa
//        long startTime = System.nanoTime();
//
//
//        byte[] paddingData = new byte[dataSize];
//        System.arraycopy(dat, 0, paddingData,0, dat.length);
//        padding.addPadding(paddingData,  dat.length);
//
//        int count = paddingData.length / engine.getBlockSize();
//
//
//        for (int i = 0; i < count ; i++) {
//            block.processBlock(paddingData,i * engine.getBlockSize(),out,i * engine.getBlockSize());
//        }
//
//        //ket thuc ma hoa
//        long durationEncTime = System.nanoTime() - startTime;
//        System.out.println("[-] Duration encrypt: " + durationEncTime +" nano second");
//
//        System.out.print("[.] Padding data : 0x");
//        for (int i = 0 ;i < paddingData.length ;i ++) {
//            System.out.format("%02x",paddingData[i]);
//        }
//
//        System.out.print("\n[.] Encrypt data output: 0x");
//        for (int i = 0 ;i < out.length ;i ++) {
//            System.out.format("%02x",out[i]);
//        }
//        System.out.println("\n");
//        return out;
//    }


//    public byte[] decryptCBC(byte[] dat, byte[] key, byte[] iv) {
//
//        System.out.println("===== Giải mã CBC =====");
//
//        AESEngine engine = new AESEngine();
//        PKCS7Padding padding = new PKCS7Padding();
//        BlockCipher block = new CBCBlockCipher(engine);
//        block.init(false, iv, key);
//        int dataSize = dat.length ;
//        byte [] decrypt =  new byte[dataSize];
//        int count = dataSize / engine.getBlockSize();
//        //tg bat dau giai ma~
//        long startTime = System.nanoTime();
//        for (int i = 0; i < count ; i++) {
//            block.processBlock(dat,i * engine.getBlockSize(),decrypt,i * engine.getBlockSize());
//        }
//
////        engine.processBlock(out,0,decrypt,0);
//        int paddingCount = padding.padCount(decrypt);
//        byte[] decryptResult = new byte[decrypt.length - paddingCount];
//        System.arraycopy(decrypt, 0, decryptResult, 0, decryptResult.length);
//        long durationDecTime = System.nanoTime() - startTime;
//        System.out.print("[-] Duration decrypt: " + durationDecTime +" nano second");
//        System.out.print("\n[.] Decrypt data output: 0x");
//        for (int i = 0 ;i < decryptResult.length ;i ++) {
//            System.out.format("%02x",decryptResult[i]);
//        }
//        System.out.println("\n[.] String result: " +new String(decryptResult));
//        return decryptResult;
//    }

//    void normal() {
//        System.out.println("===== Normal Mode ====");
//        AESEngine engine = new AESEngine();
//        PKCS7Padding padding = new PKCS7Padding();
//        byte[] key =  new byte[] {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
//        byte[] dat =  "pham hieu dep trai vo dich".getBytes(StandardCharsets.UTF_8);
//        int length = engine.getBlockSize() - (dat.length % engine.getBlockSize());
//        int dataSize = length + dat.length;
//        engine.init(true,key);
//        byte[] out = new byte[dataSize];
//        byte[] decrypt = new byte[dataSize];
//        //tg bat dau ma hoa
//        long startTime = System.nanoTime();
//        byte[] paddingData = new byte[dataSize];
//        System.arraycopy(dat, 0, paddingData,0, dat.length);
//        padding.addPadding(paddingData,  dat.length);
//        int count = paddingData.length / engine.getBlockSize();
//        for (int i = 0; i < count ; i++) {
//            engine.processBlock(paddingData,i * engine.getBlockSize(),out,i * engine.getBlockSize());
//        }
//        //ket thuc ma hoa
//        long durationEncTime = System.nanoTime() - startTime;
//        System.out.println("[-] Duration encrypt: " + durationEncTime +" nano second");
//
//        System.out.print("[.] Padding data : 0x");
//        for (int i = 0 ;i < paddingData.length ;i ++) {
//            System.out.format("%02x",paddingData[i]);
//        }
//        System.out.print("\n[.] Encrypt data output: 0x");
//        for (int i = 0 ;i < out.length ;i ++) {
//            System.out.format("%02x",out[i]);
//        }
//
//        engine.init(false,key);
//        //tg bat dau giai ma~
//        startTime = System.nanoTime();
//
//        for (int i = 0; i < count ; i++) {
//            engine.processBlock(out,i * engine.getBlockSize(),decrypt,i * engine.getBlockSize());
//        }
//
////        engine.processBlock(out,0,decrypt,0);
//
//        int paddingCount = padding.padCount(decrypt);
//
//        byte[] decryptResult = new byte[decrypt.length - paddingCount];
//
//        System.arraycopy(decrypt, 0, decryptResult, 0, decryptResult.length);
//
//        long durationDecTime = System.nanoTime() - startTime;
//        System.out.print("\n[-] Duration decrypt: " + durationDecTime +" nano second");
//        System.out.print("\n[.] Decrypt data output: 0x");
//        for (int i = 0 ;i < decryptResult.length ;i ++) {
//            System.out.format("%02x",decryptResult[i]);
//        }
//        System.out.println("\n[.] String result: " +new String(decryptResult));
//
//    }



}
