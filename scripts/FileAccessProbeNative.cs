// A held existing local file handle: observe security and read exactly one byte.
// No file creation, data/security writes, backup semantics, or retained contents.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
namespace Wela.FileAccessProbe {
 public sealed class Ace { public int Type,Flags,Mask; public string Sid,Binary; public bool Ordinary; }
 public sealed class Observation {
  public string Path,Identity,LastWriteUtc,DescriptorBase64,StateKey;
  public long Size; public uint Attributes,Links; public int SecurityInformation; public Ace[] Aces;
 }
 public sealed class ReadReceipt {
  public string StartedUtc,CompletedUtc,Clock,HandleId,BeforeKey,AfterKey;
  public int ReadCalls,BytesRead; public bool Succeeded;
 }
 sealed class SecurityPrivilege : IDisposable {
  [StructLayout(LayoutKind.Sequential)] struct Luid {public uint Low;public int High;}
  [StructLayout(LayoutKind.Sequential)] struct Privileges {public uint Count;public Luid Id;public uint Attributes;}
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenThreadToken(IntPtr thread,uint access,bool self,out IntPtr token);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out Luid luid);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool all,ref Privileges requested,uint size,out Privileges previous,out uint required);
  IntPtr token;Privileges previous;
  public SecurityPrivilege() {
   IntPtr thread;if(OpenThreadToken(GetCurrentThread(),8,true,out thread)){CloseHandle(thread);throw new InvalidOperationException("Impersonated file readers are unsupported.");}
   int error=Marshal.GetLastWin32Error();if(error!=1008)throw new Win32Exception(error);
   if(!OpenProcessToken(GetCurrentProcess(),0x28,out token))throw new Win32Exception(Marshal.GetLastWin32Error());
   try {Luid id;if(!LookupPrivilegeValue(null,"SeSecurityPrivilege",out id))throw new Win32Exception(Marshal.GetLastWin32Error());
    Privileges requested=new Privileges{Count=1,Id=id,Attributes=2};uint needed;
    bool ok=AdjustTokenPrivileges(token,false,ref requested,(uint)Marshal.SizeOf(typeof(Privileges)),out previous,out needed);
    error=Marshal.GetLastWin32Error();if(!ok||error!=0)throw new Win32Exception(error,"Existing SeSecurityPrivilege is required to inspect the SACL.");
   }catch{CloseHandle(token);token=IntPtr.Zero;throw;}
  }
  public void Dispose(){if(token==IntPtr.Zero)return;try{Privileges ignored;uint needed;bool ok=AdjustTokenPrivileges(token,false,ref previous,(uint)Marshal.SizeOf(typeof(Privileges)),out ignored,out needed);int error=Marshal.GetLastWin32Error();if(!ok||error!=0)throw new Win32Exception(error,"SACL observation privilege restoration failed.");}finally{CloseHandle(token);token=IntPtr.Zero;}}
 }
 public sealed class FileHandle : IDisposable {
  [StructLayout(LayoutKind.Sequential,Pack=4)] struct FileInfo {public uint Attributes;public long Created,Accessed,Written;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)] static extern IntPtr CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetFileType(IntPtr handle);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr handle,out FileInfo info);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)] static extern uint GetFinalPathNameByHandleW(IntPtr handle,StringBuilder path,uint length,uint flags);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadFile(IntPtr handle,[Out]byte[] buffer,uint count,out uint read,IntPtr overlapped);
  [DllImport("kernel32.dll",ExactSpelling=true)] static extern void GetSystemTimePreciseAsFileTime(out long value);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
  [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(IntPtr handle,uint kind,uint flags,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
  [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
  IntPtr handle;readonly bool canRead;bool readAttempted;readonly string selected;
  public static DateTime UtcNow(){long value;GetSystemTimePreciseAsFileTime(out value);return DateTime.FromFileTimeUtc(value);}
  public FileHandle(string path,bool readData) {
   if(String.IsNullOrEmpty(path)||path.Length>240||!System.Text.RegularExpressions.Regex.IsMatch(path,@"^[A-Za-z]:\\"))throw new InvalidOperationException("Select an ordinary absolute local file path, at most 240 characters.");
   if(path.Substring(2).IndexOf(':')>=0||path.IndexOfAny(new char[]{'"','*','?','<','>','|','/','\r','\n','\0'})>=0||!String.Equals(Path.GetFullPath(path),path,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Ambiguous file path refused.");
   string root=Path.GetPathRoot(path);if(new DriveInfo(root).DriveType!=DriveType.Fixed)throw new InvalidOperationException("Only fixed local drives are supported.");
   string part=root;foreach(string name in path.Substring(root.Length).Split('\\')) {
    if(name.Length==0||name=="."||name==".."||name.EndsWith(".")||name.EndsWith(" "))throw new InvalidOperationException("Ambiguous file component refused.");
    part=Path.Combine(part,name);if((File.GetAttributes(part)&FileAttributes.ReparsePoint)!=0)throw new InvalidOperationException("Reparse components are unsupported.");
   }
   selected=path;canRead=readData;
   try {
    // READ_CONTROL + ACCESS_SYSTEM_SECURITY + READ_ATTRIBUTES, optionally READ_DATA.
    // Share read only: reject concurrent write/delete handles while this handle is held.
    using(new SecurityPrivilege()){handle=CreateFileW(path,0x01020080U|(readData?1U:0U),1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);if(handle==new IntPtr(-1)){handle=IntPtr.Zero;throw new Win32Exception(Marshal.GetLastWin32Error());}}
    if(GetFileType(handle)!=1)throw new InvalidOperationException("The selected handle is not a disk file.");
    Observe();
   }catch{Dispose();throw;}
  }
  public Observation Observe() {
   if(handle==IntPtr.Zero)throw new ObjectDisposedException("FileHandle");
   FileInfo info;if(!GetFileInformationByHandle(handle,out info))throw new Win32Exception(Marshal.GetLastWin32Error());
   // No directories, links, EFS, offline/cloud recall, or empty data streams.
   if((info.Attributes&(16U|1024U|4096U|16384U|0x40000U|0x400000U))!=0||info.Links!=1)throw new InvalidOperationException("Only ordinary local leaf files with one link are supported.");
   long size=((long)info.SizeHigh<<32)|info.SizeLow;if(size<=0)throw new InvalidOperationException("The selected file must be nonempty.");
   StringBuilder final=new StringBuilder(32768);uint length=GetFinalPathNameByHandleW(handle,final,(uint)final.Capacity,0);
   if(length==0||length>=final.Capacity||!String.Equals(final.ToString(),@"\\?\"+selected,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("Native final file path differs from the selected local path.");
   string actual=final.ToString().Substring(4);IntPtr owner,group,dacl,sacl,descriptor;
   uint error=GetSecurityInfo(handle,1,0x1ff,out owner,out group,out dacl,out sacl,out descriptor);if(error!=0)throw new Win32Exception((int)error,"Full current SDK descriptor observation (0x1ff) failed.");
   byte[] bytes;try{uint count=GetSecurityDescriptorLength(descriptor);if(count<20||count>131072)throw new InvalidOperationException("File descriptor exceeds its observation bound.");bytes=new byte[count];Marshal.Copy(descriptor,bytes,0,(int)count);}finally{LocalFree(descriptor);}
   RawSecurityDescriptor sd=new RawSecurityDescriptor(bytes,0);List<Ace> entries=new List<Ace>();
   if(sd.SystemAcl!=null)foreach(GenericAce ace in sd.SystemAcl){if(entries.Count>=128)throw new InvalidOperationException("File SACL exceeds 128 entries.");CommonAce common=ace as CommonAce;bool ordinary=common!=null&&!common.IsCallback&&common.AceType==AceType.SystemAudit;byte[] binary=new byte[ace.BinaryLength];ace.GetBinaryForm(binary,0);entries.Add(new Ace{Type=(int)ace.AceType,Flags=(int)ace.AceFlags,Mask=ordinary?common.AccessMask:0,Sid=ordinary?common.SecurityIdentifier.Value:null,Binary=Convert.ToBase64String(binary),Ordinary=ordinary});}
   string identity=info.Volume+":"+info.IndexHigh+":"+info.IndexLow+":"+info.Created,encoded=Convert.ToBase64String(bytes),written=DateTime.FromFileTimeUtc(info.Written).ToString("o");
   string value=actual.ToUpperInvariant()+"|"+identity+"|"+size+"|"+written+"|"+info.Attributes+"|"+info.Links+"|"+encoded,key;
   using(SHA256 sha=SHA256.Create()){key=BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(value))).Replace("-","").ToLowerInvariant();}
   return new Observation{Path=actual,Identity=identity,Size=size,LastWriteUtc=written,Attributes=info.Attributes,Links=info.Links,DescriptorBase64=encoded,SecurityInformation=511,Aces=entries.ToArray(),StateKey=key};
  }
  public ReadReceipt ReadOne(string expectedKey) {
   if(!canRead||readAttempted)throw new InvalidOperationException("Exactly one explicitly requested data read is permitted.");
   Observation before=Observe();if(!String.Equals(before.StateKey,expectedKey,StringComparison.Ordinal))throw new InvalidOperationException("Selected file changed before its one-byte read.");
   byte[] buffer=new byte[1];readAttempted=true;uint count=0;DateTime started=UtcNow(),completed;bool success;int error;
   try{success=ReadFile(handle,buffer,1,out count,IntPtr.Zero);error=Marshal.GetLastWin32Error();completed=UtcNow();}finally{Array.Clear(buffer,0,buffer.Length);}
   if(!success)throw new Win32Exception(error,"The one-byte read failed.");if(count!=1)throw new InvalidOperationException("The fixed read did not return exactly one byte.");
   Observation after=Observe();if(after.StateKey!=before.StateKey)throw new InvalidOperationException("Held file identity, data metadata or descriptor changed during the read.");
   return new ReadReceipt{StartedUtc=started.ToString("o"),CompletedUtc=completed.ToString("o"),Clock="GetSystemTimePreciseAsFileTime",ReadCalls=1,BytesRead=1,Succeeded=true,HandleId="0x"+unchecked((ulong)handle.ToInt64()).ToString("x"),BeforeKey=before.StateKey,AfterKey=after.StateKey};
  }
  public void Dispose(){if(handle!=IntPtr.Zero){CloseHandle(handle);handle=IntPtr.Zero;}}
 }
}
