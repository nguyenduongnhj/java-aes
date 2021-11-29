package main;

public class main {
    public static void main(String[] args) {
        AESEngine engine = new AESEngine();
        PKCS7Padding padding = new PKCS7Padding();

        byte[] key =  new byte[] {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        byte[] dat =  new byte[] {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16, 17};
        int length = engine.getBlockSize() - (dat.length % engine.getBlockSize());
        int dataSize = length + dat.length;
        engine.init(true,key);


        byte[] out = new byte[dataSize];
        byte[] decrypt = new byte[dataSize];

        //tg bat dau ma hoa
        long startTime = System.nanoTime();

        byte[] paddingData = new byte[dataSize];
        System.arraycopy(dat, 0, paddingData,0, dat.length);
        padding.addPadding(paddingData,  dat.length);

        int count = paddingData.length / engine.getBlockSize();


        for (int i = 0; i < count ; i++) {
            engine.processBlock(paddingData,i * engine.getBlockSize(),out,i * engine.getBlockSize());
        }

        //ket thuc ma hoa
        long durationEncTime = System.nanoTime() - startTime;
        System.out.println("duration encrypt: " + durationEncTime +" nano second");


        for (int i = 0 ;i < paddingData.length ;i ++) {
            System.out.format("0x%02x ",paddingData[i]);
        }

        System.out.println("\n======\n");
        for (int i = 0 ;i < out.length ;i ++) {
            System.out.format("0x%02x ",out[i]);
        }



        engine.init(false,key);

        //tg bat dau giai ma~
        startTime = System.nanoTime();

        for (int i = 0; i < count ; i++) {
            engine.processBlock(out,i * engine.getBlockSize(),decrypt,i * engine.getBlockSize());
        }

//        engine.processBlock(out,0,decrypt,0);

        int paddingCount = padding.padCount(decrypt);

        byte[] decryptResult = new byte[decrypt.length - paddingCount];

        System.arraycopy(decrypt, 0, decryptResult, 0, decryptResult.length);

        long durationDecTime = System.nanoTime() - startTime;
        System.out.println("\nduration decrypt: " + durationDecTime +" nano second");


        System.out.println("\n======\n");
        for (int i = 0 ;i < decryptResult.length ;i ++) {
            System.out.format("0x%02x ",decryptResult[i]);
        }



    }

}
