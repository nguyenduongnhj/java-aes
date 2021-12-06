package main;

import java.security.SecureRandom;


/**
 * A padder that adds PKCS7/PKCS5 padding to a block.
 */
public class PKCS7Padding
{

    public void init(SecureRandom random)
            throws IllegalArgumentException
    {
        // nothing to do.
    }

    public String getPaddingName()
    {
        return "PKCS7";
    }

    public int addPadding(  byte[]  in, int inOff) {
        byte code = (byte)(in.length - inOff);
        while (inOff < in.length)
        {
            in[inOff] = code;
            inOff++;
        }
        return code;
    }

    public int padCount(byte[] in)
            throws InvalidCipherTextException
    {
        int count = in[in.length - 1] & 0xff;
        byte countAsbyte = (byte)count;

        // constant time version
        boolean failed = (count > in.length | count == 0);

        for (int i = 0; i < in.length; i++)
        {
            failed |= (in.length - i <= count) & (in[i] != countAsbyte);
        }

        if (failed)
        {
            throw new InvalidCipherTextException("pad block corrupted");
        }

        return count;
    }
}