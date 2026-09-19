// Local stopped-trace archival. No channel, registry, DNS or policy mutation.
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
namespace Wela.DnsAnalytical {
 public sealed class Archive {
  public string State; public string SourcePath; public string Identity; public long Length;
  public string Sha256; public string ArchivePath; public string ArchivedSha256;
 }
 public static class TraceArchive {
  [StructLayout(LayoutKind.Sequential,Pack=4)] struct FileInfo { public uint Attributes;public long Created;public long Accessed;public long Written;public uint Volume;public uint SizeHigh;public uint SizeLow;public uint Links;public uint IndexHigh;public uint IndexLow; }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out FileInfo info);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,StringBuilder path,uint size,uint flags);
  static string Hex(byte[] hash){return BitConverter.ToString(hash).Replace("-","").ToLowerInvariant();}
  static void PathGuard(string path) {
   if(String.IsNullOrEmpty(path)||path.Length<4||path[1]!=':'||path[2]!='\\'||path.Substring(2).Contains(":")||!String.Equals(Path.GetFullPath(path),path,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Archive source/output must be a canonical local drive path.");
   if(Regex.IsMatch(path,@"[\x00-\x1f*?<>|""\[\]]|[ .](\\|$)"))throw new InvalidOperationException("Archive path contains unsupported alias or wildcard syntax.");
   if(new DriveInfo(Path.GetPathRoot(path)).DriveType!=DriveType.Fixed)throw new InvalidOperationException("Archive path requires a local fixed drive.");
   string current=Path.GetDirectoryName(path);
   while(!String.IsNullOrEmpty(current)) {
    FileAttributes attributes=File.GetAttributes(current);
    if((attributes&FileAttributes.ReparsePoint)!=0)throw new InvalidOperationException("Archive path traverses a reparse point.");
    if((attributes&FileAttributes.Directory)==0)throw new InvalidOperationException("Archive parent is not a directory.");
    string next=Path.GetDirectoryName(current);if(next==current)break;current=next;
   }
  }
  static FileInfo Info(SafeFileHandle handle,string path) {
   FileInfo info;if(!GetFileInformationByHandle(handle,out info))throw new Win32Exception(Marshal.GetLastWin32Error(),"Cannot identify trace handle.");
   if((info.Attributes&0x410)!=0)throw new InvalidOperationException("Trace must be a regular non-reparse file.");
   StringBuilder final=new StringBuilder(32768);uint size=GetFinalPathNameByHandle(handle,final,(uint)final.Capacity,0);
   if(size==0||size>=final.Capacity||!String.Equals(final.ToString(),"\\\\?\\"+path,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Final trace handle path differs from the selected local path.");
   return info;
  }
  static string Identity(FileInfo info){return info.Volume+":"+info.IndexHigh+":"+info.IndexLow+":"+info.Created+":"+info.Written;}
  public static Archive Inspect(string source,long maximumBytes) { return Read(source,null,maximumBytes); }
  public static Archive Read(string source,string destination,long maximumBytes) {
   if(maximumBytes<1048576||maximumBytes>4294967296L)throw new InvalidOperationException("Archive cap must be between 1 MiB and 4 GiB.");
   PathGuard(source);if(destination!=null)PathGuard(destination);
   // No writer/delete sharing. A stopped trace that cannot be exclusively read is unknown, never empty.
   SafeFileHandle handle=CreateFile(source,0x80000000,1,IntPtr.Zero,3,0x08200000,IntPtr.Zero);
   if(handle.IsInvalid){int error=Marshal.GetLastWin32Error();handle.Dispose();if(error==2)return new Archive{State="ObservedAbsent",SourcePath=source};throw new Win32Exception(error,"Trace absence was not established (only FILE_NOT_FOUND is accepted).");}
   using(handle) {
    FileInfo info=Info(handle,source);long length=((long)info.SizeHigh<<32)|info.SizeLow;
    if(length<=0)throw new InvalidOperationException("Existing trace has no readable ETL bytes; no empty archive is fabricated.");
    if(length>maximumBytes)throw new InvalidOperationException("Trace exceeds the explicit archive byte cap; no truncation is allowed.");
    using(FileStream input=new FileStream(handle,FileAccess.Read,65536,false)) {
     FileStream output=null;
     try {
      if(destination!=null)output=new FileStream(destination,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None,65536,FileOptions.SequentialScan);
      byte[] buffer=new byte[65536];long total=0;string hash;
      using(SHA256 sha=SHA256.Create()) {
       int read;while((read=input.Read(buffer,0,buffer.Length))!=0) {
        total+=read;if(total>maximumBytes||total>length)throw new InvalidOperationException("Trace size changed while archiving.");
        sha.TransformBlock(buffer,0,read,buffer,0);if(output!=null)output.Write(buffer,0,read);
       }
       sha.TransformFinalBlock(new byte[0],0,0);hash=Hex(sha.Hash);
      }
      if(total!=length||Identity(Info(handle,source))!=Identity(info))throw new InvalidOperationException("Trace identity or size changed during archive.");
      string archived=null;
      if(output!=null) {
       output.Flush(true);output.Position=0;using(SHA256 sha=SHA256.Create()){archived=Hex(sha.ComputeHash(output));}
       Info(output.SafeFileHandle,destination);
       if(output.Length!=length||archived!=hash)throw new InvalidOperationException("Archived bytes failed readback verification.");
      }
      return new Archive {State=destination==null?"ObservedBytes":"ArchivedBytes",SourcePath=source,Identity=Identity(info),Length=length,Sha256=hash,ArchivePath=destination,ArchivedSha256=archived};
     } finally {if(output!=null)output.Dispose();}
    }
   }
  }
 }
}
