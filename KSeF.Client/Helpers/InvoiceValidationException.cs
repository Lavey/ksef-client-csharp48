using System;
namespace KSeF.Client.Helpers
{
public class InvoiceValidationException : Exception
{
    public InvoiceValidationException(string message) : base(message)
    {
    }
}
}
