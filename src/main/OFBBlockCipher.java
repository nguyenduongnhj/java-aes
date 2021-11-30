package main;

public class OFBBlockCipher implements BlockCipher{

    private int             byteCount;
    private byte[]          IV;
    private byte[]          ofbV;
    private byte[]          ofbOutV;

    private final int             blockSize;
    private final AESEngine     cipher;

    public OFBBlockCipher( AESEngine cipher) {
        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();
        this.IV = new byte[cipher.getBlockSize()];
        this.ofbV = new byte[cipher.getBlockSize()];
        this.ofbOutV = new byte[cipher.getBlockSize()];
    }

    public int getBlockSize() {
        return blockSize;
    }

    @Override
    public void init(boolean forEncryption, byte[] iv, byte[] key) throws IllegalArgumentException {
        System.arraycopy(iv, 0, IV, 0, IV.length);
        reset();
        cipher.init(true, key);
    }

    public int processBlock(  byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        processBytes(in, inOff, blockSize, out, outOff);
        return blockSize;
    }

    public void reset() {
        System.arraycopy(IV, 0, ofbV, 0, IV.length);
        byteCount = 0;
        cipher.reset();
    }

    protected byte calculateByte(byte in) throws DataLengthException, IllegalStateException {
        if (byteCount == 0)
        {
            cipher.processBlock(ofbV, 0, ofbOutV, 0);
        }
        byte rv = (byte)(ofbOutV[byteCount++] ^ in);

        if (byteCount == blockSize)
        {
            byteCount = 0;

            System.arraycopy(ofbV, blockSize, ofbV, 0, ofbV.length - blockSize);
            System.arraycopy(ofbOutV, 0, ofbV, ofbV.length - blockSize, blockSize);
        }

        return rv;
    }

    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException {
        if (inOff + len > in.length)
        {
            throw new DataLengthException("input buffer too small");
        }
        if (outOff + len > out.length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        int inStart = inOff;
        int inEnd = inOff + len;
        int outStart = outOff;
        while (inStart < inEnd)
        {
            out[outStart++] = calculateByte(in[inStart++]);
        }
        return len;
    }
}
