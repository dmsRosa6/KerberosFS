package org.example.Crypto;

public class CryptoException extends Exception 
{
     public CryptoException() {}
   
     public CryptoException(String message) 
     {
        super(message);
     }
}