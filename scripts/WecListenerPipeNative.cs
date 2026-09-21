using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
namespace Wela.ListenerPipe {
    public static class Bounded {
        public const string SourceSha256 = "__WELA_SOURCE_SHA256__";
        public static async Task<string> Read(TextReader reader, int maximumCharacters) {
            if (reader == null || maximumCharacters < 1 || maximumCharacters > 1048576) throw new ArgumentException("Invalid bounded reader.");
            var text = new StringBuilder(); var buffer = new char[1024];
            while (true) {
                int count = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                if (count == 0) return text.ToString();
                if (count > maximumCharacters - text.Length) throw new InvalidDataException("Native listener adapter output exceeded its character bound.");
                text.Append(buffer, 0, count);
            }
        }
    }
}
