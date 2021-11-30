package main;

public interface BlockCipher {

    public void init(boolean forEncryption, byte[] iv, byte[] key)
            throws IllegalArgumentException;

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
            throws DataLengthException, IllegalStateException;

    public int getBlockSize();

    public void reset();
}
