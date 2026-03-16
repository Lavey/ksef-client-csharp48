
using System;
namespace KSeF.Client.Compatibility
{
/// <summary>
/// Polyfill dla właściwości <c>Random.Shared</c> dostępnej od .NET 6.
/// Używa <c>[ThreadStatic]</c> dla bezpiecznych wątkowo instancji per-wątek.
/// </summary>
internal static class RandomCompat
{
    [ThreadStatic]
    private static Random _shared;

    /// <summary>
    /// Pobiera bezpieczną wątkowo współdzieloną instancję <see cref="Random"/>.
    /// </summary>
    public static Random Shared
    {
        get
        {
            if (_shared == null) _shared = new Random();
            return _shared;
        }
    }
}

}
