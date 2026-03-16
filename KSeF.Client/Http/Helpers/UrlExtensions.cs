using System;
using System.Collections.Generic;
using System.Text;

namespace KSeF.Client.Http.Helpers
{
internal static class UrlExtensions
{
    public static string WithQuery(this string path, IDictionary<string, string> query, Uri baseAddress)
    {
        string baseUri = baseAddress?.AbsoluteUri.TrimEnd('/');
        string uri = Uri.IsWellFormedUriString(path, UriKind.Absolute)
            ? path
            : (baseUri == null ? path : baseUri + "/" + path.TrimStart('/'));

        if (query == null || query.Count == 0)
        {
            return uri;
        }

        StringBuilder builder = new(uri);
        builder.Append(uri.Contains('?') ? "&" : "?");

        bool first = true;
        foreach (KeyValuePair<string, string> pair in query)
        {
            if (!first)
            {
                builder.Append('&');
            }

            first = false;
            string name = Uri.EscapeDataString(pair.Key);
            string value = pair.Value == null ? string.Empty : Uri.EscapeDataString(pair.Value);
            builder.Append(name).Append('=').Append(value);
        }
        return builder.ToString();
    }
}


}
