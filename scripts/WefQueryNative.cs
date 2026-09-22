// Read-only native Event Log query and bounded output helpers.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Principal;
using System.Threading.Tasks;
namespace Wela.WefQuery {
 public sealed class LogStatus { public string Channel; public uint Error; }
 public sealed class Result {
  public bool Opened, Complete, Capped, CleanupConfirmed=true;
  public uint? NativeError; public string Diagnostic="";
  public LogStatus[] Channels=new LogStatus[0], DiagnosticChannels=new LogStatus[0];
  public uint? DiagnosticNativeError;
  public string[] Events=new string[0];
 }
 public static class Native {
  public const string SourceSha256="__WELA_WEF_QUERY_SHA256__";
  const int MaximumBuffer=1048576;
  [DllImport("wevtapi.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] static extern IntPtr EvtQuery(IntPtr session,string path,string query,uint flags);
  [DllImport("wevtapi.dll",ExactSpelling=true,SetLastError=true)] static extern bool EvtGetQueryInfo(IntPtr query,int property,uint size,IntPtr buffer,out uint used);
  [DllImport("wevtapi.dll",ExactSpelling=true,SetLastError=true)] static extern bool EvtNext(IntPtr query,uint size,[Out] IntPtr[] events,uint timeout,uint flags,out uint returned);
  [DllImport("wevtapi.dll",ExactSpelling=true,SetLastError=true)] static extern bool EvtRender(IntPtr context,IntPtr value,uint flags,uint size,IntPtr buffer,out uint used,out uint count);
  [DllImport("wevtapi.dll",ExactSpelling=true,SetLastError=true)] static extern bool EvtClose(IntPtr value);
  static int Offset(IntPtr buffer,int used,IntPtr value,long length) {
   long offset=value.ToInt64()-buffer.ToInt64();
   if(value==IntPtr.Zero||offset<16||length<0||offset>used||length>used-offset)throw new InvalidDataException("Native pointer escapes its returned query buffer.");
   return (int)offset;
  }
  static string Text(IntPtr buffer,int used,IntPtr value,int maximum) {
   int offset=Offset(buffer,used,value,2);if((offset&1)!=0)throw new InvalidDataException("Unaligned native UTF16 string.");
   int length=0;while(length<=maximum&&offset+2L*length+2<=used){if(Marshal.ReadInt16(buffer,offset+2*length)==0){byte[] bytes=new byte[length*2];Marshal.Copy(value,bytes,0,bytes.Length);return new UnicodeEncoding(false,false,true).GetString(bytes);}length++;}
   throw new InvalidDataException("Unterminated or oversized native query name.");
  }
  static int Header(IntPtr buffer,int used,int expected) {
   if(buffer==IntPtr.Zero||used<16||used>MaximumBuffer||Marshal.ReadInt32(buffer,12)!=expected)throw new InvalidDataException("Unexpected native query variant type or size.");
   int count=Marshal.ReadInt32(buffer,8);if(count<0||count>128)throw new InvalidDataException("Native query status count exceeds 128.");return count;
  }
  // EVT (not EC) UInt32 is 8; arrays require the exact array bit.
  public static string[] DecodeNames(IntPtr buffer,int used) {
   int count=Header(buffer,used,129);IntPtr values=Marshal.ReadIntPtr(buffer);string[] result=new string[count];
   if(count>0){Offset(buffer,used,values,(long)count*IntPtr.Size);for(int i=0;i<count;i++){result[i]=Text(buffer,used,Marshal.ReadIntPtr(values,i*IntPtr.Size),1024);if(result[i].Length==0)throw new InvalidDataException("Empty native query channel.");}}
   return result;
  }
  public static uint[] DecodeStatuses(IntPtr buffer,int used) {
   int count=Header(buffer,used,136);IntPtr values=Marshal.ReadIntPtr(buffer);uint[] result=new uint[count];
   if(count>0){Offset(buffer,used,values,(long)count*4);for(int i=0;i<count;i++)result[i]=unchecked((uint)Marshal.ReadInt32(values,i*4));}return result;
  }
  static object Info(IntPtr query,int property) {
   uint size=0;for(int attempt=0;attempt<4;attempt++){
    IntPtr buffer=size==0?IntPtr.Zero:Marshal.AllocHGlobal((int)size);
    try{uint used;bool ok=EvtGetQueryInfo(query,property,size,buffer,out used);int error=Marshal.GetLastWin32Error();
     if(ok){if(used<16||used>size)throw new InvalidDataException("Native query returned an invalid used length.");return property==0?(object)DecodeNames(buffer,(int)used):DecodeStatuses(buffer,(int)used);}
     if(error!=122)throw new Win32Exception(error);if(used<=size||used>MaximumBuffer)throw new InvalidDataException("Native query buffer bound exceeded.");size=used;
    }finally{if(buffer!=IntPtr.Zero)Marshal.FreeHGlobal(buffer);}
   }throw new InvalidDataException("Native query buffer did not stabilize.");
  }
  static LogStatus[] Statuses(IntPtr query) {
   string[] names=(string[])Info(query,0);uint[] codes=(uint[])Info(query,1);
   if(names.Length!=codes.Length||names.Length==0)throw new InvalidDataException("Incomplete native query channel status arrays.");
   LogStatus[] result=new LogStatus[names.Length];for(int i=0;i<names.Length;i++)result[i]=new LogStatus {Channel=names[i],Error=codes[i]};return result;
  }
  static string Render(IntPtr value) {
   uint size=0;for(int attempt=0;attempt<4;attempt++){
    IntPtr buffer=size==0?IntPtr.Zero:Marshal.AllocHGlobal((int)size);
    try{uint used,count;bool ok=EvtRender(IntPtr.Zero,value,1,size,buffer,out used,out count);int error=Marshal.GetLastWin32Error();
     if(ok){if(used<2||used>size||(used&1)!=0)throw new InvalidDataException("Native event XML byte boundary differs: used="+used+", allocated="+size+".");if(count!=0)throw new InvalidDataException("Native XML PropertyCount is "+count+", expected zero.");if(Marshal.ReadInt16(buffer,(int)used-2)!=0)throw new InvalidDataException("Native event XML lacks the final UTF16 terminator: used="+used+", allocated="+size+", finalWord="+Marshal.ReadInt16(buffer,(int)used-2)+".");byte[] bytes=new byte[used-2];Marshal.Copy(buffer,bytes,0,bytes.Length);string xml=new UnicodeEncoding(false,false,true).GetString(bytes);if(xml.IndexOf('\0')>=0)throw new InvalidDataException("Embedded NUL in event XML.");return xml;}
     if(error!=122)throw new Win32Exception(error);if(used<=size||used>MaximumBuffer)throw new InvalidDataException("Native event XML exceeds one MiB.");size=used;
    }finally{if(buffer!=IntPtr.Zero)Marshal.FreeHGlobal(buffer);}
   }throw new InvalidDataException("Native event XML buffer did not stabilize.");
  }
  static void Close(IntPtr handle,Result result) {if(handle!=IntPtr.Zero&&!EvtClose(handle)){result.CleanupConfirmed=false;result.Complete=false;result.Diagnostic+=" Native query/event handle close failed.";}}
  public static Result Read(string query,int maximum) {
   if(String.IsNullOrEmpty(query)||query.Length>65536||maximum<1||maximum>64)throw new ArgumentException("Query text/event count exceeds the explicit bound.");
   Result result=new Result();List<string> events=new List<string>();IntPtr handle=IntPtr.Zero;
   try{
    // Local log query, reverse order. Never tolerate errors for matching evidence.
    handle=EvtQuery(IntPtr.Zero,null,query,0x201);
    if(handle==IntPtr.Zero){result.NativeError=unchecked((uint)Marshal.GetLastWin32Error());
     // Diagnostic-only alternate query. Windows may recover parts of invalid XPath.
     IntPtr diagnostic=EvtQuery(IntPtr.Zero,null,query,0x1201);
     if(diagnostic==IntPtr.Zero)result.DiagnosticNativeError=unchecked((uint)Marshal.GetLastWin32Error());
     else try{result.DiagnosticChannels=Statuses(diagnostic);}catch(Exception e){result.Diagnostic+=" Diagnostic status read failed: "+e.Message;}finally{Close(diagnostic,result);}
     return result;
    }
    result.Opened=true;result.Channels=Statuses(handle);long bytes=0;
    while(true){IntPtr[] next=new IntPtr[1];uint returned=0;bool ok=EvtNext(handle,1,next,5000,0,out returned);int error=Marshal.GetLastWin32Error();
     try{
      if(!ok){if(returned!=0||next[0]!=IntPtr.Zero)throw new InvalidDataException("Failed EvtNext returned an unexpected event.");if(error==259)result.Complete=true;else result.NativeError=unchecked((uint)error);break;}
      if(returned!=1||next[0]==IntPtr.Zero)throw new InvalidDataException("EvtNext returned an invalid count or handle.");
      if(events.Count==maximum){result.Capped=true;break;}
      string xml=Render(next[0]);bytes+=Encoding.UTF8.GetByteCount(xml);if(bytes>4194304)throw new InvalidDataException("Native matching XML exceeds four MiB aggregate.");events.Add(xml);
     }finally{Close(next[0],result);}
    }
   }catch(Win32Exception e){result.NativeError=unchecked((uint)e.NativeErrorCode);result.Complete=false;result.Diagnostic+=e.Message;}
   catch(Exception e){result.Complete=false;result.Diagnostic+=e.Message;}
   finally{Close(handle,result);if(!result.CleanupConfirmed)result.Complete=false;result.Events=events.ToArray();}
   return result;
  }
  public static async Task<string> ReadPipe(TextReader reader,int maximum) {
   var text=new StringBuilder();var buffer=new char[2048];while(true){int count=await reader.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false);if(count==0)return text.ToString();if(count>maximum-text.Length)throw new InvalidDataException("Worker output exceeds its bound.");text.Append(buffer,0,count);}
  }
 }
}

namespace Wela.WefQueryToken {
 public sealed class Group { public string Sid; public uint Attributes; }
 public sealed class Privilege { public string Luid; public uint Attributes; }
 public sealed class Token {
  public string Sid, Name, AuthenticationId, AuthenticationType, ImpersonationLevel, TokenSource;
  public Group[] Groups; public Privilege[] Privileges;
 }
 public static class Native {
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
