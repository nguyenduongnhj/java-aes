package main;

public class CBCBlockCipher
{
    private byte[]          IV;
    private byte[]          cbcV;
    private byte[]          cbcNextV;

    private int             blockSize;
    private AESEngine        cipher = null;
    private boolean         encrypting;

    public CBCBlockCipher( AESEngine cipher)
    {
        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();
        this.IV = new byte[blockSize];
        this.cbcV = new byte[blockSize];
        this.cbcNextV = new byte[blockSize];
    }

    public void init( boolean encrypting, byte[] iv) throws IllegalArgumentException {
        boolean oldEncrypting = this.encrypting;

        this.encrypting = encrypting;
        if (iv.length != blockSize)
        {
            throw new IllegalArgumentException("initialisation vector must be the same length as block size");
        }

        System.arraycopy(iv, 0, IV, 0, iv.length);

        reset();
    }


    public int processBlock(
            byte[]      in,
            int         inOff,
            byte[]      out,
            int         outOff)
            throws DataLengthException, IllegalStateException
    {
        return (encrypting) ? encryptBlock(in, inOff, out, outOff) : decryptBlock(in, inOff, out, outOff);
    }

    public void reset()
    {
        System.arraycopy(IV, 0, cbcV, 0, IV.length);
        Arrays.fill(cbcNextV, (byte)0);

        cipher.reset();
    }

    private int encryptBlock(
            byte[]      in,
            int         inOff,
            byte[]      out,
            int         outOff)
            throws DataLengthException, IllegalStateException
    {
        if ((inOff + blockSize) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        /*
         * XOR the cbcV and the input,
         * then encrypt the cbcV
         */
        for (int i = 0; i < blockSize; i++)
        {
            cbcV[i] ^= in[inOff + i];
        }

        int length = cipher.processBlock(cbcV, 0, out, outOff);
        System.arraycopy(out, outOff, cbcV, 0, cbcV.length);

        return length;
    }

    private int decryptBlock(
            byte[]      in,
            int         inOff,
            byte[]      out,
            int         outOff)
            throws DataLengthException, IllegalStateException
    {
        if ((inOff + blockSize) > in.length)
        {
            throw new DataLengthException("input buffer too short");
        }

        System.arraycopy(in, inOff, cbcNextV, 0, blockSize);

        int length = cipher.processBlock(in, inOff, out, outOff);


         // XOR the cbcV and the output

        for (int i = 0; i < blockSize; i++)
        {
            out[outOff + i] ^= cbcV[i];
        }

        byte[]  tmp;

        tmp = cbcV;
        cbcV = cbcNextV;
        cbcNextV = tmp;

        return length;
    }
}
