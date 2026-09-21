// Read-only process-token observations. No privilege or authorization changes.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace Wela.WmiProbe {
 public sealed class Group { public string Sid; public uint Attributes; }
 public sealed class Privilege { public string Luid; public uint Attributes; }
 public sealed class Token {
  public string Sid, Name, AuthenticationId, AuthenticationType, ImpersonationLevel, TokenSource;
  public Group[] Groups; public Privilege[] Privileges;
 }
 public static class Native {
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
    try {if(length<Marshal.SizeOf(typeof(Statistics)))throw new InvalidOperationException("Truncated token statistics.");result.AuthenticationId=Hex(((Statistics)Marshal.PtrToStructure(p,typeof(Statistics))).AuthenticationId);}finally{Marshal.FreeHGlobal(p);}
    p=Read(token,2,out length);
    try {int count=Marshal.ReadInt32(p),offset=(int)Marshal.OffsetOf(typeof(TokenGroups),"First"),size=Marshal.SizeOf(typeof(SidAndAttributes));if(count<0||count>4096||offset+(long)count*size>length)throw new InvalidOperationException("Invalid token groups.");List<Group> groups=new List<Group>();for(int i=0;i<count;i++){SidAndAttributes g=(SidAndAttributes)Marshal.PtrToStructure(IntPtr.Add(p,offset+i*size),typeof(SidAndAttributes));groups.Add(new Group{Sid=new SecurityIdentifier(g.Sid).Value,Attributes=g.Attributes});}groups.Sort((a,b)=>String.CompareOrdinal(a.Sid,b.Sid));result.Groups=groups.ToArray();}finally{Marshal.FreeHGlobal(p);}
    p=Read(token,3,out length);
    try {int count=Marshal.ReadInt32(p),size=Marshal.SizeOf(typeof(LuidAndAttributes));if(count<0||count>4096||4+(long)count*size>length)throw new InvalidOperationException("Invalid token privileges.");List<Privilege> privileges=new List<Privilege>();for(int i=0;i<count;i++){LuidAndAttributes v=(LuidAndAttributes)Marshal.PtrToStructure(IntPtr.Add(p,4+i*size),typeof(LuidAndAttributes));privileges.Add(new Privilege{Luid=Hex(v.Luid),Attributes=v.Attributes});}privileges.Sort((a,b)=>String.CompareOrdinal(a.Luid,b.Luid));result.Privileges=privileges.ToArray();}finally{Marshal.FreeHGlobal(p);}
    return result;
  }
  static bool Equivalent(Token a,Token b) {
   if(a.Sid!=b.Sid||a.AuthenticationId!=b.AuthenticationId||a.Groups.Length!=b.Groups.Length||a.Privileges.Length!=b.Privileges.Length)return false;
   for(int i=0;i<a.Groups.Length;i++)if(a.Groups[i].Sid!=b.Groups[i].Sid||a.Groups[i].Attributes!=b.Groups[i].Attributes)return false;
   for(int i=0;i<a.Privileges.Length;i++)if(a.Privileges[i].Luid!=b.Privileges[i].Luid||a.Privileges[i].Attributes!=b.Privileges[i].Attributes)return false;
   return true;
  }
  static string Difference(Token a,Token b) {
   if(a.Sid!=b.Sid)return "user SID differs";
   if(a.AuthenticationId!=b.AuthenticationId)return "logon LUID differs";
   if(a.Groups.Length!=b.Groups.Length)return "group count differs";
   for(int i=0;i<a.Groups.Length;i++)if(a.Groups[i].Sid!=b.Groups[i].Sid||a.Groups[i].Attributes!=b.Groups[i].Attributes)return "group "+a.Groups[i].Sid+" process="+a.Groups[i].Attributes+" effective="+b.Groups[i].Attributes;
   if(a.Privileges.Length!=b.Privileges.Length)return "privilege count differs";
   for(int i=0;i<a.Privileges.Length;i++)if(a.Privileges[i].Luid!=b.Privileges[i].Luid||a.Privileges[i].Attributes!=b.Privileges[i].Attributes)return "privilege "+a.Privileges[i].Luid+" process="+a.Privileges[i].Attributes+" effective="+b.Privileges[i].Attributes;
   return "unknown difference";
  }
  [DllImport("advapi32.dll")] static extern bool IsTokenRestricted(IntPtr token);
  public static Token Snapshot() {
   IntPtr thread=IntPtr.Zero,process=IntPtr.Zero;
   if(!OpenThreadToken(GetCurrentThread(),8,true,out thread)){int error=Marshal.GetLastWin32Error();if(error!=1008)throw new Win32Exception(error);}
   try {
    if(!OpenProcessToken(GetCurrentProcess(),8,out process))throw new Win32Exception(Marshal.GetLastWin32Error());
    if(IsTokenRestricted(process)||(thread!=IntPtr.Zero&&IsTokenRestricted(thread)))throw new InvalidOperationException("Restricted tokens are unsupported.");
    Token primary=ReadToken(process,"Process");
    if(thread==IntPtr.Zero)return primary;
    Token effective=ReadToken(thread,"EquivalentSelfThread");
    if(!Equivalent(primary,effective))throw new InvalidOperationException("Effective thread token differs from the process token ("+Difference(primary,effective)+"); an ordinary child cannot preserve this caller context.");
    return effective;
   } finally {if(process!=IntPtr.Zero)CloseHandle(process);if(thread!=IntPtr.Zero)CloseHandle(thread);}
  }
 }
}
