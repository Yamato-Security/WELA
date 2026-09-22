// Read-only process-token observations. No privilege or authorization changes.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace Wela.AppLockerScript {
 public sealed class Group { public string Sid; public uint Attributes; }
 public sealed class Privilege { public string Luid; public uint Attributes; }
 public sealed class Token {
  public string Sid, Name, TokenId, ModifiedId, AuthenticationId, AuthenticationType, ImpersonationLevel, TokenSource;
  public Group[] Groups; public Privilege[] Privileges;
 }
 public static class Native {
  public const string SourceSha256="__WELA_SOURCE_SHA256__";
  [DllImport("kernel32.dll",ExactSpelling=true)] static extern void GetSystemTimePreciseAsFileTime(out long value);
  public static DateTime UtcNow() {long value;GetSystemTimePreciseAsFileTime(out value);return DateTime.FromFileTimeUtc(value);}
  [StructLayout(LayoutKind.Sequential)] struct Luid {public uint Low; public int High;}
  [StructLayout(LayoutKind.Sequential)] struct Statistics {public Luid TokenId,AuthenticationId;public long Expiration;public int Type,Level;public uint Charged,Available,Groups,Privileges;public Luid Modified;}
  [StructLayout(LayoutKind.Sequential)] struct SidAndAttributes {public IntPtr Sid;public uint Attributes;}
  [StructLayout(LayoutKind.Sequential)] struct TokenGroups {public uint Count;public SidAndAttributes First;}
  [StructLayout(LayoutKind.Sequential)] struct LuidAndAttributes {public Luid Luid;public uint Attributes;}
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint access,out IntPtr t);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenThreadToken(IntPtr p,uint access,bool self,out IntPtr t);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr t,int cls,IntPtr data,int length,out int needed);
  static string Hex(Luid id) {return "0x"+(((ulong)(uint)id.High<<32)|id.Low).ToString("x");}
  static IntPtr Read(IntPtr token,int cls,out int length) {
   GetTokenInformation(token,cls,IntPtr.Zero,0,out length);
   if(Marshal.GetLastWin32Error()!=122||length<4||length>65536)throw new InvalidOperationException("Unknown or oversized token information.");
   IntPtr data=Marshal.AllocHGlobal(length);
   if(!GetTokenInformation(token,cls,data,length,out length)){int error=Marshal.GetLastWin32Error();Marshal.FreeHGlobal(data);throw new Win32Exception(error);}
   return data;
  }
  static Token ReadToken(IntPtr token,string source) {
    Token result=new Token();result.TokenSource=source;using(WindowsIdentity identity=new WindowsIdentity(token)){result.Sid=identity.User.Value;result.Name=identity.Name;result.AuthenticationType=identity.AuthenticationType;result.ImpersonationLevel=identity.ImpersonationLevel.ToString();}
    int length;IntPtr p=Read(token,10,out length);
    try {if(length<Marshal.SizeOf(typeof(Statistics)))throw new InvalidOperationException("Truncated token statistics.");Statistics stats=(Statistics)Marshal.PtrToStructure(p,typeof(Statistics));if(stats.Type!=1)throw new InvalidOperationException("A primary token is required.");result.AuthenticationId=Hex(stats.AuthenticationId);result.TokenId=Hex(stats.TokenId);result.ModifiedId=Hex(stats.Modified);}finally{Marshal.FreeHGlobal(p);}
    p=Read(token,2,out length);
    try {int count=Marshal.ReadInt32(p),offset=(int)Marshal.OffsetOf(typeof(TokenGroups),"First"),size=Marshal.SizeOf(typeof(SidAndAttributes));if(count<0||count>4096||offset+(long)count*size>length)throw new InvalidOperationException("Invalid token groups.");List<Group> groups=new List<Group>();for(int i=0;i<count;i++){SidAndAttributes g=(SidAndAttributes)Marshal.PtrToStructure(IntPtr.Add(p,offset+i*size),typeof(SidAndAttributes));groups.Add(new Group{Sid=new SecurityIdentifier(g.Sid).Value,Attributes=g.Attributes});}groups.Sort((a,b)=>String.CompareOrdinal(a.Sid,b.Sid));result.Groups=groups.ToArray();}finally{Marshal.FreeHGlobal(p);}
    p=Read(token,3,out length);
    try {int count=Marshal.ReadInt32(p),size=Marshal.SizeOf(typeof(LuidAndAttributes));if(count<0||count>4096||4+(long)count*size>length)throw new InvalidOperationException("Invalid token privileges.");List<Privilege> privileges=new List<Privilege>();for(int i=0;i<count;i++){LuidAndAttributes v=(LuidAndAttributes)Marshal.PtrToStructure(IntPtr.Add(p,4+i*size),typeof(LuidAndAttributes));privileges.Add(new Privilege{Luid=Hex(v.Luid),Attributes=v.Attributes});}privileges.Sort((a,b)=>String.CompareOrdinal(a.Luid,b.Luid));result.Privileges=privileges.ToArray();}finally{Marshal.FreeHGlobal(p);}
    return result;
  }
  public static Token Child(IntPtr handle) {
   IntPtr token=IntPtr.Zero;
   if(!OpenProcessToken(handle,8,out token))throw new Win32Exception(Marshal.GetLastWin32Error());
   try {if(IsTokenRestricted(token))throw new InvalidOperationException("Restricted child token unsupported.");return ReadToken(token,"ChildProcess");}finally{CloseHandle(token);}
  }
  [DllImport("advapi32.dll")] static extern bool IsTokenRestricted(IntPtr token);
  public static Token Snapshot() {
   IntPtr thread=IntPtr.Zero,process=IntPtr.Zero;
   if(OpenThreadToken(GetCurrentThread(),8,true,out thread)){CloseHandle(thread);throw new InvalidOperationException("Impersonated callers are unsupported.");}
   int error=Marshal.GetLastWin32Error();if(error!=1008)throw new Win32Exception(error);
   if(!OpenProcessToken(GetCurrentProcess(),8,out process))throw new Win32Exception(Marshal.GetLastWin32Error());
   try {if(IsTokenRestricted(process))throw new InvalidOperationException("Restricted caller unsupported.");return ReadToken(process,"Process");}finally{CloseHandle(process);}
  }
  [StructLayout(LayoutKind.Sequential)] struct FileInformation {
   public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;
   public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
  }
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr file,out FileInformation info);
  public static string FileId(IntPtr handle) {
   FileInformation info;if(!GetFileInformationByHandle(handle,out info))throw new Win32Exception(Marshal.GetLastWin32Error());
   if((info.Attributes&0x410)!=0)throw new InvalidOperationException("One ordinary non-reparse file identity is required.");
   return info.Volume.ToString("x8")+":"+info.IndexHigh.ToString("x8")+info.IndexLow.ToString("x8");
  }
  public static async System.Threading.Tasks.Task<string> ReadLineBoundedAsync(System.IO.StreamReader reader,int limit) {
   char[] buffer=new char[1];System.Text.StringBuilder text=new System.Text.StringBuilder();
   while(true){int count=await reader.ReadAsync(buffer,0,1).ConfigureAwait(false);if(count==0)throw new InvalidOperationException("Owned child ended before its ready marker.");if(buffer[0]=='\n')return text.ToString().TrimEnd('\r');if(text.Length>=limit)throw new InvalidOperationException("Owned child line exceeds the bound.");text.Append(buffer[0]);}
  }
  public static async System.Threading.Tasks.Task<string> ReadBoundedAsync(System.IO.StreamReader reader,int limit) {
   char[] buffer=new char[256];System.Text.StringBuilder text=new System.Text.StringBuilder();
   while(true){int count=await reader.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false);if(count==0)return text.ToString();if(text.Length+count>limit)throw new InvalidOperationException("Owned child output exceeds the bound.");text.Append(buffer,0,count);}
  }
 }
}
