package main;

public class OutputLengthException
        extends RuntimeException
{

    public OutputLengthException()
    {
    }

    public OutputLengthException(
            String  message)
    {
        super(message);
    }
}