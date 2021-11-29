package main;


public class InvalidCipherTextException
        extends RuntimeException
{

    public InvalidCipherTextException()
    {
    }

    public InvalidCipherTextException(
            String  message)
    {
        super(message);
    }
}