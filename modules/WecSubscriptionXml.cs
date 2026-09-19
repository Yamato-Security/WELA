// Explicit Unicode native XML reads, independent of the PowerShell console code page.
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
namespace Wela.WecXml {
 public static class Reader {
  static async Task<byte[]> ReadBounded(Stream stream,int maximum) {
   using(MemoryStream output=new MemoryStream()) {
    byte[] buffer=new byte[8192];int count;
    while((count=await stream.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false))!=0) {
     if(output.Length+count>maximum)throw new IOException("Native WEC output exceeds its byte limit.");
     output.Write(buffer,0,count);
    }
    return output.ToArray();
   }
  }
  public static string DecodeXml(byte[] bytes) {
   if(bytes==null||bytes.Length==0||bytes.Length>10485760||bytes.Length%2!=0)throw new InvalidDataException("Expected bounded UTF-16LE WEC XML bytes.");
   int skip=bytes.Length>=2&&bytes[0]==255&&bytes[1]==254?2:0;
   string text=new UnicodeEncoding(false,false,true).GetString(bytes,skip,bytes.Length-skip);
   if(!text.TrimStart(' ','\t','\r','\n').StartsWith("<",StringComparison.Ordinal))throw new InvalidDataException("Native WEC Unicode output is not XML.");
   return text;
  }
  public static string ReadXml(string id) {
   if(id==null||!Regex.IsMatch(id,@"\A[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}\z"))throw new ArgumentException("Select one exact supported subscription ID.");
   ProcessStartInfo start=new ProcessStartInfo();start.FileName=Path.Combine(Environment.SystemDirectory,"wecutil.exe");
   start.Arguments="gs \""+id+"\" /f:xml /uni:true";start.UseShellExecute=false;start.CreateNoWindow=true;start.RedirectStandardOutput=true;start.RedirectStandardError=true;
   using(Process process=new Process()) {
    process.StartInfo=start;bool started=false;
    try {
     started=process.Start();if(!started)throw new IOException("Native WEC process did not start.");
     Stopwatch timer=Stopwatch.StartNew();Task<byte[]> output=ReadBounded(process.StandardOutput.BaseStream,10485760);Task<byte[]> error=ReadBounded(process.StandardError.BaseStream,65536);
     while(!process.WaitForExit(100)) {
      if(output.IsFaulted||error.IsFaulted)throw new IOException("Native WEC output could not be read within its bounds.");
      if(timer.ElapsedMilliseconds>=30000)throw new TimeoutException("Native WEC definition read exceeded thirty seconds.");
     }
     int remaining=Math.Max(1,30000-(int)timer.ElapsedMilliseconds);
     if(!Task.WaitAll(new Task[]{output,error},remaining))throw new TimeoutException("Native WEC output did not complete within thirty seconds.");
     if(process.ExitCode!=0)throw new IOException("Native WEC definition read failed with exit code "+process.ExitCode+"; no definition was accepted.");
     if(error.Result.Length!=0)throw new IOException("Native WEC returned unexpected diagnostic bytes; no definition was accepted.");
     return DecodeXml(output.Result);
    } finally {
     if(started){try{if(!process.HasExited){process.Kill();process.WaitForExit(1000);}}catch(InvalidOperationException){}}
    }
   }
  }
 }
}
