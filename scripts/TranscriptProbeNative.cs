// Read-only local identity/descriptor/file access and bounded pipe drains.
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
namespace Wela.TranscriptProbe {
 public sealed class Observation {
  public string Path, Identity, CreatedUtc, WrittenUtc, Descriptor;
  public uint Attributes, Links; public long Length;
 }
 public sealed class Capture {public string Text, Error;public bool Exceeded;}
 public sealed class Item : IDisposable {
  [StructLayout(LayoutKind.Sequential,Pack=4)] struct Info {public uint Attributes;public long Created,Accessed,Written;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Info value);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,StringBuilder text,uint length,uint flags);
  [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(SafeFileHandle handle,uint kind,uint flags,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
  [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
  SafeFileHandle handle; FileStream stream; string path; bool directory;
  public const string SourceSha256 = "__WELA_TRANSCRIPT_SOURCE_SHA256__";
  Item(string path,bool directory,bool content) {
   this.path=System.IO.Path.GetFullPath(path);this.directory=directory;
   handle=CreateFile(this.path,content?0x80020000u:0x20080u,directory?3u:(content?1u:7u),IntPtr.Zero,3,0x02200000,IntPtr.Zero);
   if(handle.IsInvalid){int error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error);}
   try {Snapshot();if(content)stream=new FileStream(handle,FileAccess.Read,4096,false);}catch{Dispose();throw;}
  }
  public static Item Directory(string path){return new Item(path,true,false);}
  public static Item Metadata(string path){return new Item(path,false,false);}
  public static Item File(string path){return new Item(path,false,true);}
  public Observation Snapshot() {
   Info value;if(!GetFileInformationByHandle(handle,out value))throw new Win32Exception(Marshal.GetLastWin32Error());
   if((value.Attributes&1024)!=0||((value.Attributes&16)!=0)!=directory)throw new InvalidOperationException("Unexpected reparse point or object type.");
   if(!directory&&value.Links!=1)throw new InvalidOperationException("Transcript files must have one link.");
   StringBuilder buffer=new StringBuilder(32768);uint length=GetFinalPathNameByHandle(handle,buffer,(uint)buffer.Capacity,0);
   if(length==0||length>=buffer.Capacity)throw new InvalidOperationException("Unknown native object path.");
   string final=buffer.ToString();if(final.StartsWith(@"\\?\",StringComparison.Ordinal))final=final.Substring(4);
   if(!String.Equals(final.TrimEnd('\\'),path.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Native object path changed or resolves elsewhere.");
   IntPtr owner,group,dacl,sacl,sd;uint error=GetSecurityInfo(handle,1,7,out owner,out group,out dacl,out sacl,out sd);
   if(error!=0)throw new Win32Exception((int)error);
   string descriptor;
   try {uint size=GetSecurityDescriptorLength(sd);if(size<20||size>65536)throw new InvalidOperationException("Invalid descriptor bound.");byte[] bytes=new byte[size];Marshal.Copy(sd,bytes,0,bytes.Length);descriptor=Convert.ToBase64String(bytes);}finally{LocalFree(sd);}
   return new Observation{Path=final,Identity=value.Volume.ToString("x8")+":"+value.IndexHigh.ToString("x8")+value.IndexLow.ToString("x8"),CreatedUtc=DateTime.FromFileTimeUtc(value.Created).ToString("o"),WrittenUtc=DateTime.FromFileTimeUtc(value.Written).ToString("o"),Attributes=value.Attributes,Links=value.Links,Length=((long)value.SizeHigh<<32)|value.SizeLow,Descriptor=descriptor};
  }
  public byte[] Read(int maximum) {
   if(stream==null)throw new InvalidOperationException("Object was not opened for content.");
   Observation before=Snapshot();if(before.Length<1||before.Length>maximum)throw new InvalidOperationException("Transcript is empty or exceeds its byte bound.");
   byte[] bytes=new byte[(int)before.Length];stream.Position=0;int offset=0;
   while(offset<bytes.Length){int read=stream.Read(bytes,offset,bytes.Length-offset);if(read==0)throw new EndOfStreamException();offset+=read;}
   if(stream.ReadByte()!=-1)throw new InvalidOperationException("Transcript grew while reading.");
   Observation after=Snapshot();if(before.Length!=after.Length||before.Identity!=after.Identity||before.WrittenUtc!=after.WrittenUtc||before.Descriptor!=after.Descriptor)throw new InvalidOperationException("Transcript changed while reading.");
   return bytes;
  }
  public void Dispose(){if(stream!=null){stream.Dispose();stream=null;}if(handle!=null){handle.Dispose();handle=null;}}
  public static Task<Capture> Drain(TextReader reader,int maximum) {
   return Task.Factory.StartNew(()=>{Capture result=new Capture();StringBuilder text=new StringBuilder();char[] buffer=new char[2048];
    try {int count;while((count=reader.Read(buffer,0,buffer.Length))>0){int retain=Math.Min(count,Math.Max(0,maximum-text.Length));if(retain<count)result.Exceeded=true;if(retain>0)text.Append(buffer,0,retain);}}
    catch(Exception error){result.Error=error.GetType().FullName;}
    result.Text=text.ToString();return result;});
  }
 }
}
