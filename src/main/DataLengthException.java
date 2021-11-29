package main;

public class DataLengthException
        extends RuntimeException
{

    public DataLengthException()
    {
    }


    public DataLengthException(
            String  message)
    {
        super(message);
    }
}