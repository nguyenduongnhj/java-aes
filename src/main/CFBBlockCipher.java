package main;

public class CFBBlockCipher implements BlockCipher {
    private byte[]          IV;
    private byte[]          cfbV;
    private byte[]          cfbOutV;
    private byte[]          inBuf;

    private int             blockSize;
    private AESEngine       cipher;
    private boolean         encrypting;
    private int             byteCount;

    public CFBBlockCipher( AESEngine cipher )
    {
        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();
        this.IV = new byte[cipher.getBlockSize()];
        this.cfbV = new byte[cipher.getBlockSize()];
        this.cfbOutV = new byte[cipher.getBlockSize()];
        this.inBuf = new byte[blockSize];
    }


    protected byte calculateByte(byte in) throws DataLengthException, IllegalStateException {
        return (encrypting) ? encryptByte(in) : decryptByte(in);
    }

    private byte encryptByte(byte in) {
        if (byteCount == 0)
        {
            cipher.processBlock(cfbV, 0, cfbOutV, 0);
        }

        byte rv = (byte)(cfbOutV[byteCount] ^ in);
        inBuf[byteCount++] = rv;
        if (byteCount == blockSize)
        {
            byteCount = 0;

            System.arraycopy(cfbV, blockSize, cfbV, 0, cfbV.length - blockSize);
            System.arraycopy(inBuf, 0, cfbV, cfbV.length - blockSize, blockSize);
        }
        return rv;
    }

    private byte decryptByte(byte in)
    {
        if (byteCount == 0)
        {
            cipher.processBlock(cfbV, 0, cfbOutV, 0);
        }

        inBuf[byteCount] = in;
        byte rv = (byte)(cfbOutV[byteCount++] ^ in);

        if (byteCount == blockSize)
        {
            byteCount = 0;

            System.arraycopy(cfbV, blockSize, cfbV, 0, cfbV.length - blockSize);
            System.arraycopy(inBuf, 0, cfbV, cfbV.length - blockSize, blockSize);
        }

        return rv;
    }

    @Override
    public void init(boolean forEncryption, byte[] iv, byte[] key) throws IllegalArgumentException {
        this.encrypting = forEncryption;
        if (iv.length < IV.length)
        {
            System.arraycopy(iv, 0, IV, IV.length - iv.length, iv.length);
            for (int i = 0; i < IV.length - iv.length; i++)
            {
                IV[i] = 0;
            }
        }
        else
        {
            System.arraycopy(iv, 0, IV, 0, IV.length);
        }
        reset();
        cipher.init(true, key);
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        processBytes(in, inOff, blockSize, out, outOff);
        return blockSize;
    }

    @Override
    public int getBlockSize() {
        return cipher.getBlockSize();
    }

    public int encryptBlock( byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        processBytes(in, inOff, blockSize, out, outOff);
        return blockSize;
    }

    public int decryptBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        processBytes(in, inOff, blockSize, out, outOff);
        return blockSize;
    }

    public byte[] getCurrentIV() {
        return Arrays.clone(cfbV);
    }

    public void reset() {
        System.arraycopy(IV, 0, cfbV, 0, IV.length);
        Arrays.fill(inBuf, (byte)0);
        byteCount = 0;
        cipher.reset();
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
